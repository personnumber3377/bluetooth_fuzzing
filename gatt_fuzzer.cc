/*
 * Stateful multi-client GATT fuzzer for Android Bluetooth stack.
 *
 * Drop-in replacement idea for your current gatt_fuzzer.cc.  This keeps the
 * same fake stack shape, but adds:
 *   - scripted ATT transactions instead of only raw packet feeding
 *   - app-side GATTS responses from p_req_cb
 *   - BR/EDR dynamic L2CAP callback driving through appl_info
 *   - fixed-channel congestion callback driving
 *   - client API operation driving
 *   - better handle-aware ATT PDU generation
 *
 * Notes:
 *   - This intentionally avoids touching private static functions directly.
 *   - Some Android tree revisions rename fields slightly. If a tGATTS_DATA or
 *     tGATTS_RSP field name differs in your checkout, adjust only the small
 *     RespondToServerRequest() helper.
 *   - Keep your existing gatt_mutator.c next to this file. This harness still
 *     includes it, so libFuzzer can use your packet-aware mutator.
 */

#include <base/functional/callback.h>
#include <base/location.h>
#include <bluetooth/log.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "osi/include/allocator.h"
#include "stack/include/bt_hdr.h"
#include "stack/include/bt_uuid16.h"
#include "stack/include/gatt_api.h"
// include/bt_psm_types.h
#include "stack/include/bt_psm_types.h" // Here is the types...
#include "stack/gatt/gatt_int.h"
#include "test/fake/fake_osi.h"
#include "test/mock/mock_btif_config.h"
#include "test/mock/mock_stack_acl.h"
#include "test/mock/mock_stack_btm_dev.h"
#include "test/mock/mock_stack_l2cap_api.h"
#include "test/mock/mock_stack_l2cap_ble.h"
#include "test/mock/mock_stack_l2cap_interface.h"

#include "gatt_mutator.c"

// This is here for ignoring the leak of the object in the fake bluetooth stack. Ugly but works for now...
#include <gmock/gmock.h>

using bluetooth::Uuid;
using ::testing::_;
using ::testing::NiceMock;
using ::testing::Unused;

// Used for the different actions...
enum Action {
    CONNECT,
    DISCONNECT,
    OPEN_EATT,
    CLOSE_EATT,
    SEND_ATT,
    CONGEST,
};

bt_status_t do_in_main_thread(base::OnceCallback<void()> cb) {
  if (cb) std::move(cb).Run();
  return BT_STATUS_SUCCESS;
}

bt_status_t do_in_main_thread_delayed(base::OnceCallback<void()> cb,
                                      std::chrono::microseconds) {
  if (cb) std::move(cb).Run();
  return BT_STATUS_SUCCESS;
}

namespace bluetooth {
namespace os {
bool GetSystemPropertyBool(const std::string&, bool default_value) { return default_value; }
uint32_t GetSystemPropertyUint32(const std::string&, uint32_t default_value) {
  return default_value;
}
}  // namespace os
}  // namespace bluetooth

namespace {

constexpr uint16_t kMaxPacketSize = 1024;
constexpr size_t kMaxPeers = 8;
constexpr uint16_t kDynStartCid = 0x0040;
constexpr uint16_t kFakePsm = BT_PSM_ATT;

std::array<RawAddress, kMaxPeers> kPeerAddrs = {
    RawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x60}),
    RawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x61}),
    RawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x62}),
    RawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x63}),
    RawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x64}),
    RawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x65}),
    RawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x66}),
    RawAddress({0x11, 0x22, 0x33, 0x44, 0x55, 0x67}),
};

// Captured from L2CAP registration.
tL2CAP_FIXED_CHNL_REG fixed_chnl_reg;
tL2CAP_APPL_INFO appl_info;
tBTM_SEC_DEV_REC btm_sec_dev_rec;

static tGATT_IF s_AppIf = 0;
static std::array<uint16_t, kMaxPeers> s_ConnIds;
static std::array<bool, kMaxPeers> s_Connected;
static std::array<uint16_t, kMaxPeers> s_DynCid;

static int PeerIndexFromAddr(const RawAddress& addr) {
  for (size_t i = 0; i < kPeerAddrs.size(); i++) {
    if (kPeerAddrs[i] == addr) return static_cast<int>(i);
  }
  return -1;
}

static uint16_t GetConnId(size_t peer) {
  if (peer >= kMaxPeers) return 0;
  return s_ConnIds[peer];
}

/*
static uint16_t Le16(uint8_t lo, uint8_t hi) {
  return static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
}
*/

static void PutLe16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>(v & 0xff));
  out.push_back(static_cast<uint8_t>(v >> 8));
}

static uint16_t PickHandle(FuzzedDataProvider& fdp) {
  static constexpr std::array<uint16_t, 16> handles = {
      0x0000, 0x0001, 0x0002, 0x0003,
      0x0010, 0x0011, 0x0012, 0x0013,
      GATT_GAP_START_HANDLE,
      static_cast<uint16_t>(GATT_GAP_START_HANDLE + 1),
      static_cast<uint16_t>(GATT_GAP_START_HANDLE + 2),
      GATT_GATT_START_HANDLE,
      static_cast<uint16_t>(GATT_GATT_START_HANDLE + 1),
      0x00ff, 0x0100, 0xffff,
  };
  return handles[fdp.ConsumeIntegralInRange<size_t>(0, handles.size() - 1)];
}

static uint16_t PickUuid16(FuzzedDataProvider& fdp) {
  static constexpr std::array<uint16_t, 14> uuids = {
      UUID_SERVCLASS_GAP_SERVER,
      UUID_SERVCLASS_GATT_SERVER,
      GATT_UUID_GAP_DEVICE_NAME,
      GATT_UUID_GAP_ICON,
      GATT_UUID_GAP_PREF_CONN_PARAM,
      GATT_UUID_GAP_CENTRAL_ADDR_RESOL,
      GATT_UUID_PRI_SERVICE,
      GATT_UUID_SEC_SERVICE,
      GATT_UUID_INCLUDE_SERVICE,
      GATT_UUID_CHAR_DECLARE,
      GATT_UUID_CHAR_CLIENT_CONFIG,
      GATT_UUID_CHAR_SRVR_CONFIG,
      0x0000,
      0xffff,
  };
  return uuids[fdp.ConsumeIntegralInRange<size_t>(0, uuids.size() - 1)];
}

static std::vector<uint8_t> ConsumeValue(FuzzedDataProvider& fdp, size_t max_len = 256) {
  const size_t len = fdp.ConsumeIntegralInRange<size_t>(0, max_len);
  return fdp.ConsumeBytes<uint8_t>(len);
}

static BT_HDR* MakeHdr(const std::vector<uint8_t>& bytes, uint16_t offset = 0) {
  BT_HDR* hdr = static_cast<BT_HDR*>(osi_calloc(sizeof(BT_HDR) + offset + bytes.size()));
  hdr->offset = offset;
  hdr->len = bytes.size();
  std::copy(bytes.cbegin(), bytes.cend(), reinterpret_cast<uint8_t*>(hdr + 1) + offset);
  return hdr;
}

static std::vector<uint8_t> AttExchangeMtu(FuzzedDataProvider& fdp, bool response = false) {
  std::vector<uint8_t> p;
  p.push_back(response ? GATT_RSP_MTU : GATT_REQ_MTU);
  static constexpr std::array<uint16_t, 12> mtus = {0, 1, 2, 3, 23, 24, 64, 128, 247, 512, 517, 0xffff};
  PutLe16(p, mtus[fdp.ConsumeIntegralInRange<size_t>(0, mtus.size() - 1)]);
  return p;
}

static std::vector<uint8_t> AttFindInfoReq(FuzzedDataProvider& fdp) {
  std::vector<uint8_t> p = {GATT_REQ_FIND_INFO};
  uint16_t start = PickHandle(fdp);
  uint16_t end = fdp.ConsumeBool() ? PickHandle(fdp) : static_cast<uint16_t>(start + 16);
  PutLe16(p, start);
  PutLe16(p, end);
  return p;
}

static std::vector<uint8_t> AttReadByTypeReq(FuzzedDataProvider& fdp) {
  std::vector<uint8_t> p = {GATT_REQ_READ_BY_TYPE};
  uint16_t start = PickHandle(fdp);
  uint16_t end = fdp.ConsumeBool() ? PickHandle(fdp) : static_cast<uint16_t>(start + 32);
  PutLe16(p, start);
  PutLe16(p, end);
  if (fdp.ConsumeBool()) {
    PutLe16(p, PickUuid16(fdp));
  } else {
    auto uuid = fdp.ConsumeBytes<uint8_t>(Uuid::kNumBytes128);
    p.insert(p.end(), uuid.begin(), uuid.end());
  }
  return p;
}

static std::vector<uint8_t> AttReadByGroupTypeReq(FuzzedDataProvider& fdp) {
  std::vector<uint8_t> p = {GATT_REQ_READ_BY_GRP_TYPE};
  uint16_t start = PickHandle(fdp);
  uint16_t end = fdp.ConsumeBool() ? PickHandle(fdp) : 0xffff;
  PutLe16(p, start);
  PutLe16(p, end);
  if (fdp.ConsumeBool()) {
    PutLe16(p, GATT_UUID_PRI_SERVICE);
  } else {
    auto uuid = fdp.ConsumeBytes<uint8_t>(Uuid::kNumBytes128);
    p.insert(p.end(), uuid.begin(), uuid.end());
  }
  return p;
}

static std::vector<uint8_t> AttReadReq(FuzzedDataProvider& fdp, bool blob = false) {
  std::vector<uint8_t> p = {static_cast<uint8_t>(blob ? GATT_REQ_READ_BLOB : GATT_REQ_READ)};
  PutLe16(p, PickHandle(fdp));
  if (blob) PutLe16(p, fdp.ConsumeIntegral<uint16_t>());
  return p;
}

static std::vector<uint8_t> AttReadMultiReq(FuzzedDataProvider& fdp, bool variable) {
  std::vector<uint8_t> p = {static_cast<uint8_t>(variable ? GATT_REQ_READ_MULTI_VAR : GATT_REQ_READ_MULTI)};
  const size_t n = fdp.ConsumeIntegralInRange<size_t>(0, variable ? 12 : 16);
  for (size_t i = 0; i < n; i++) PutLe16(p, PickHandle(fdp));
  return p;
}

static std::vector<uint8_t> AttWriteReq(FuzzedDataProvider& fdp, uint8_t opcode = GATT_REQ_WRITE) {
  std::vector<uint8_t> p = {opcode};
  PutLe16(p, PickHandle(fdp));
  auto value = ConsumeValue(fdp, 256);
  p.insert(p.end(), value.begin(), value.end());
  return p;
}

static std::vector<uint8_t> AttPrepareWriteReq(FuzzedDataProvider& fdp) {
  std::vector<uint8_t> p = {GATT_REQ_PREPARE_WRITE};
  PutLe16(p, PickHandle(fdp));
  PutLe16(p, fdp.ConsumeIntegral<uint16_t>());
  auto value = ConsumeValue(fdp, 128);
  p.insert(p.end(), value.begin(), value.end());
  return p;
}

static std::vector<uint8_t> AttExecuteWriteReq(FuzzedDataProvider& fdp) {
  return {GATT_REQ_EXEC_WRITE, static_cast<uint8_t>(fdp.ConsumeBool() ? 0x01 : 0x00)};
}

static std::vector<uint8_t> AttFindByTypeValueReq(FuzzedDataProvider& fdp) {
  std::vector<uint8_t> p = {GATT_REQ_FIND_TYPE_VALUE};
  uint16_t start = PickHandle(fdp);
  uint16_t end = fdp.ConsumeBool() ? PickHandle(fdp) : 0xffff;
  PutLe16(p, start);
  PutLe16(p, end);
  PutLe16(p, fdp.ConsumeBool() ? GATT_UUID_PRI_SERVICE : PickUuid16(fdp));
  auto value = ConsumeValue(fdp, 64);
  p.insert(p.end(), value.begin(), value.end());
  return p;
}

static std::vector<uint8_t> AttHandleValueConfirmation() {
  return {GATT_HANDLE_VALUE_CONF};
}

static std::vector<uint8_t> RandomOrStructuredPdu(FuzzedDataProvider& fdp) {
  switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 12)) {
    case 0: return AttExchangeMtu(fdp, false);
    case 1: return AttExchangeMtu(fdp, true);
    case 2: return AttFindInfoReq(fdp);
    case 3: return AttFindByTypeValueReq(fdp);
    case 4: return AttReadByTypeReq(fdp);
    case 5: return AttReadByGroupTypeReq(fdp);
    case 6: return AttReadReq(fdp, false);
    case 7: return AttReadReq(fdp, true);
    case 8: return AttReadMultiReq(fdp, false);
    case 9: return AttReadMultiReq(fdp, true);
    case 10: return AttWriteReq(fdp, GATT_REQ_WRITE);
    case 11: return AttPrepareWriteReq(fdp);
    case 12: return AttExecuteWriteReq(fdp);
    default: return ConsumeValue(fdp, kMaxPacketSize);
  }
}

static void ResetHarnessState() {
  fixed_chnl_reg = tL2CAP_FIXED_CHNL_REG{};
  appl_info = tL2CAP_APPL_INFO{};
  btm_sec_dev_rec = tBTM_SEC_DEV_REC{};
  s_AppIf = 0;
  s_ConnIds.fill(0);
  s_Connected.fill(false);
  s_DynCid.fill(0);
}

class FakeBtStack {
  NiceMock<bluetooth::testing::stack::l2cap::Mock> mock_l2cap_interface;

 public:
  FakeBtStack() {
    
    // Yuck!

    /*
    testing::Mock::AllowLeak(&mock_l2cap_interface);

    test::mock::stack_btm_dev::btm_find_dev.body =
        [](const RawAddress&) {
            return &btm_sec_dev_rec;
        };
    */

    test::mock::stack_btm_dev::btm_find_dev.body = [](const RawAddress&) {
      return &btm_sec_dev_rec;
    };

    test::mock::stack_l2cap_ble::L2CA_GetBleConnRole.body = [](const RawAddress&) {
      return HCI_ROLE_CENTRAL;
    };

    ON_CALL(mock_l2cap_interface, L2CA_SetIdleTimeoutByBdAddr)
        .WillByDefault([](Unused, Unused, Unused) { return true; });

    ON_CALL(mock_l2cap_interface, L2CA_RemoveFixedChnl)
        .WillByDefault([](uint16_t, Unused) { return true; });

    ON_CALL(mock_l2cap_interface, L2CA_ConnectFixedChnl)
        .WillByDefault([](Unused, Unused) { return true; });

    ON_CALL(mock_l2cap_interface, L2CA_DataWrite)
        .WillByDefault([](Unused, BT_HDR* hdr) {
          osi_free(hdr);
          return tL2CAP_DW_RESULT::SUCCESS;
        });

    ON_CALL(mock_l2cap_interface, L2CA_DisconnectReq)
        .WillByDefault([](Unused) { return true; });

    ON_CALL(mock_l2cap_interface, L2CA_SendFixedChnlData)
        .WillByDefault([](Unused, Unused, BT_HDR* hdr) {
          osi_free(hdr);
          return tL2CAP_DW_RESULT::SUCCESS;
        });

    ON_CALL(mock_l2cap_interface, L2CA_RegisterFixedChannel)
        .WillByDefault([](Unused, tL2CAP_FIXED_CHNL_REG* p_freg) {
          fixed_chnl_reg = *p_freg;
          return true;
        });

    ON_CALL(mock_l2cap_interface, L2CA_RegisterWithSecurity)
        .WillByDefault([](uint16_t psm, const tL2CAP_APPL_INFO& p_cb_info, Unused,
                          Unused, Unused, Unused, Unused) {
          appl_info = p_cb_info;
          return psm;
        });

    ON_CALL(mock_l2cap_interface, L2CA_RegisterLECoc)
        .WillByDefault([](uint16_t psm, Unused, Unused, Unused) { return psm; });

    ON_CALL(mock_l2cap_interface, L2CA_SetLeGattTimeout)
        .WillByDefault([](Unused, Unused) { return true; });

    bluetooth::testing::stack::l2cap::set_interface(&mock_l2cap_interface);
  }

  ~FakeBtStack() {
    test::mock::stack_btm_dev::btm_find_dev = {};
    test::mock::stack_l2cap_ble::L2CA_GetBleConnRole = {};
    bluetooth::testing::stack::l2cap::reset_interface();
  }
};

class Fakes {
 public:
  test::fake::FakeOsi fake_osi;
  FakeBtStack fake_stack;
};

static void RespondToServerRequest(uint16_t conn_id, uint32_t trans_id,
                                   tGATTS_REQ_TYPE type, tGATTS_DATA* data) {
  tGATTS_RSP rsp{};
  tGATT_STATUS status = GATT_SUCCESS;

  switch (type) {
    case GATTS_REQ_TYPE_READ_CHARACTERISTIC:
    case GATTS_REQ_TYPE_READ_DESCRIPTOR: {
      // Most Android revisions use attr_value for read responses.
      rsp.attr_value.handle = data ? data->read_req.handle : 0;
      rsp.attr_value.offset = data ? data->read_req.offset : 0;
      rsp.attr_value.len = 8;
      for (uint16_t i = 0; i < rsp.attr_value.len; i++) {
        rsp.attr_value.value[i] = static_cast<uint8_t>(0x41 + i);
      }
      break;
    }

    case GATTS_REQ_TYPE_WRITE_CHARACTERISTIC:
    case GATTS_REQ_TYPE_WRITE_DESCRIPTOR:
    case GATTS_REQ_TYPE_WRITE_EXEC: {
      // Successful empty response. This is enough to drive
      // gatt_sr_process_app_rsp(), prepare-write counters, and response send paths.
      break;
    }

    default: {
      status = GATT_NOT_FOUND;
      break;
    }
  }

  (void)GATTS_SendRsp(conn_id, trans_id, status, &rsp);
}

static void GattInit(bool eatt_support = false) {
  ResetHarnessState();
  gatt_init();

  gatt_cb.over_br_enabled = true;

  /*
  appl_info = {
      gatt_l2cif_connect_ind_cback,
      gatt_l2cif_connect_cfm_cback,
      gatt_l2cif_config_ind_cback,
      gatt_l2cif_config_cfm_cback,
      gatt_l2cif_disconnect_ind_cback,
      nullptr,
      gatt_l2cif_data_ind_cback,
      gatt_l2cif_congest_cback,
      nullptr,
      gatt_on_l2cap_error,
      nullptr,
      nullptr,
      nullptr,
      nullptr,
  };
  */

  std::array<uint8_t, Uuid::kNumBytes128> tmp;
  tmp.fill(0x82);
  Uuid app_uuid = Uuid::From128BitBE(tmp);

  tGATT_CBACK app_cback = {
      .p_conn_cb = [](tGATT_IF, const RawAddress& bda, uint16_t conn_id, bool connected,
                      tGATT_DISCONN_REASON, tBT_TRANSPORT) {
        int idx = PeerIndexFromAddr(bda);
        if (idx >= 0) {
          s_ConnIds[idx] = connected ? conn_id : 0;
          s_Connected[idx] = connected;
        }
      },
      .p_cmpl_cb = [](uint16_t, tGATTC_OPTYPE, tGATT_STATUS, tGATT_CL_COMPLETE*) {},
      .p_disc_res_cb = [](uint16_t, tGATT_DISC_TYPE, tGATT_DISC_RES*) {},
      .p_disc_cmpl_cb = [](uint16_t, tGATT_DISC_TYPE, tGATT_STATUS) {},
      .p_req_cb = [](uint16_t conn_id, uint32_t trans_id, tGATTS_REQ_TYPE type,
                     tGATTS_DATA* data) { RespondToServerRequest(conn_id, trans_id, type, data); },
      .p_enc_cmpl_cb = [](tGATT_IF, const RawAddress&) {},
      .p_congestion_cb = [](uint16_t, bool) {},
      .p_phy_update_cb = [](tGATT_IF, uint16_t, uint8_t, uint8_t, tGATT_STATUS) {},
      .p_conn_update_cb = [](tGATT_IF, uint16_t, uint16_t, uint16_t, uint16_t,
                             tGATT_STATUS) {},
      .p_subrate_chg_cb = [](tGATT_IF, uint16_t, uint16_t, uint16_t, uint16_t,
                             uint16_t, tGATT_STATUS) {},
  };

  s_AppIf = GATT_Register(app_uuid, "StatefulGattFuzzer", &app_cback, eatt_support);
  GATT_StartIf(s_AppIf);
}

static void ServerInit(bool eatt_support) {
  GattInit(eatt_support);

  tGATT_APPL_INFO gatt_appl_info = {
      .p_nv_save_callback = [](bool, tGATTS_HNDL_RANGE*) {},
      .p_srv_chg_callback = [](tGATTS_SRV_CHG_CMD, tGATTS_SRV_CHG_REQ*,
                               tGATTS_SRV_CHG_RSP*) { return true; },
  };

  (void)GATTS_NVRegister(&gatt_appl_info);

  Uuid gap_uuid = Uuid::From16Bit(UUID_SERVCLASS_GAP_SERVER);
  Uuid gatt_uuid = Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER);
  Uuid name_uuid = Uuid::From16Bit(GATT_UUID_GAP_DEVICE_NAME);
  Uuid icon_uuid = Uuid::From16Bit(GATT_UUID_GAP_ICON);
  Uuid ppcp_uuid = Uuid::From16Bit(GATT_UUID_GAP_PREF_CONN_PARAM);
  Uuid car_uuid = Uuid::From16Bit(GATT_UUID_GAP_CENTRAL_ADDR_RESOL);
  Uuid cccd_uuid = Uuid::From16Bit(GATT_UUID_CHAR_CLIENT_CONFIG);

  btgatt_db_element_t db[] = {
      {.uuid = gap_uuid, .type = BTGATT_DB_PRIMARY_SERVICE},
      {.uuid = name_uuid,
       .type = BTGATT_DB_CHARACTERISTIC,
       .properties = static_cast<uint8_t>(GATT_CHAR_PROP_BIT_READ | GATT_CHAR_PROP_BIT_WRITE),
       .permissions = static_cast<uint16_t>(GATT_PERM_READ | GATT_PERM_WRITE)},
      {.uuid = cccd_uuid,
       .type = BTGATT_DB_DESCRIPTOR,
       .permissions = static_cast<uint16_t>(GATT_PERM_READ | GATT_PERM_WRITE)},
      {.uuid = icon_uuid,
       .type = BTGATT_DB_CHARACTERISTIC,
       .properties = static_cast<uint8_t>(GATT_CHAR_PROP_BIT_READ),
       .permissions = GATT_PERM_READ},
      {.uuid = ppcp_uuid,
       .type = BTGATT_DB_CHARACTERISTIC,
       .properties = static_cast<uint8_t>(GATT_CHAR_PROP_BIT_READ),
       .permissions = GATT_PERM_READ},
      {.uuid = car_uuid,
       .type = BTGATT_DB_CHARACTERISTIC,
       .properties = static_cast<uint8_t>(GATT_CHAR_PROP_BIT_READ | GATT_CHAR_PROP_BIT_WRITE),
       .permissions = static_cast<uint16_t>(GATT_PERM_READ | GATT_PERM_WRITE)},
      {.uuid = gatt_uuid, .type = BTGATT_DB_PRIMARY_SERVICE},
  };

  (void)GATTS_AddService(s_AppIf, db, sizeof(db) / sizeof(db[0]));
}

static void CleanupGatt() {
  if (s_AppIf != 0) {
    GATT_Deregister(s_AppIf);
  }
  gatt_free();
  ResetHarnessState();
}

static void ConnectPeer(size_t peer, tBT_TRANSPORT transport = BT_TRANSPORT_LE) {
  if (peer >= kMaxPeers || !fixed_chnl_reg.pL2CA_FixedConn_Cb) return;
  fixed_chnl_reg.pL2CA_FixedConn_Cb(L2CAP_ATT_CID, kPeerAddrs[peer], true, 0, transport);
}

static void DisconnectPeer(size_t peer, tBT_TRANSPORT transport = BT_TRANSPORT_LE,
                           uint16_t reason = 0x13) {
  if (peer >= kMaxPeers || !fixed_chnl_reg.pL2CA_FixedConn_Cb) return;
  fixed_chnl_reg.pL2CA_FixedConn_Cb(L2CAP_ATT_CID, kPeerAddrs[peer], false, reason, transport);
  s_Connected[peer] = false;
  s_ConnIds[peer] = 0;
}

static void FeedFixedPeerPacket(size_t peer, const std::vector<uint8_t>& bytes) {
  if (peer >= kMaxPeers || !fixed_chnl_reg.pL2CA_FixedData_Cb) return;
  BT_HDR* hdr = MakeHdr(bytes);
  fixed_chnl_reg.pL2CA_FixedData_Cb(L2CAP_ATT_CID, kPeerAddrs[peer], hdr);
}

static void FixedCongestion(size_t peer, bool congested) {
  if (peer >= kMaxPeers || !fixed_chnl_reg.pL2CA_FixedCong_Cb) return;
  fixed_chnl_reg.pL2CA_FixedCong_Cb(kPeerAddrs[peer], congested);
}

static void DynamicConnectPeer(size_t peer, FuzzedDataProvider& fdp) {
  if (peer >= kMaxPeers || !appl_info.pL2CA_ConnectInd_Cb) return;
  uint16_t cid = static_cast<uint16_t>(kDynStartCid + peer +
                                       16 * fdp.ConsumeIntegralInRange<uint16_t>(0, 8));
  s_DynCid[peer] = cid;
  uint8_t l2cap_id = fdp.ConsumeIntegral<uint8_t>();
  appl_info.pL2CA_ConnectInd_Cb(kPeerAddrs[peer], cid, kFakePsm, l2cap_id);

  if (appl_info.pL2CA_ConnectCfm_Cb) {
    appl_info.pL2CA_ConnectCfm_Cb(cid, tL2CAP_CONN::L2CAP_CONN_OK);
  }

  if (appl_info.pL2CA_ConfigInd_Cb) {
    tL2CAP_CFG_INFO cfg{};
    cfg.mtu_present = true;
    cfg.mtu = fdp.ConsumeIntegralInRange<uint16_t>(23, GATT_MAX_MTU_SIZE);
    appl_info.pL2CA_ConfigInd_Cb(cid, &cfg);
  }

  if (appl_info.pL2CA_ConfigCfm_Cb) {
    tL2CAP_CFG_INFO cfg{};
    cfg.mtu_present = true;
    cfg.mtu = fdp.ConsumeIntegralInRange<uint16_t>(23, GATT_MAX_MTU_SIZE);
    appl_info.pL2CA_ConfigCfm_Cb(cid, 0, &cfg);
  }
}

static void DynamicDisconnectPeer(size_t peer, bool ack_needed) {
  if (peer >= kMaxPeers || s_DynCid[peer] == 0 || !appl_info.pL2CA_DisconnectInd_Cb) return;
  appl_info.pL2CA_DisconnectInd_Cb(s_DynCid[peer], ack_needed);
  s_DynCid[peer] = 0;
}

static void FeedDynamicPeerPacket(size_t peer, const std::vector<uint8_t>& bytes) {
  if (peer >= kMaxPeers || s_DynCid[peer] == 0 || !appl_info.pL2CA_DataInd_Cb) return;
  BT_HDR* hdr = MakeHdr(bytes);
  appl_info.pL2CA_DataInd_Cb(s_DynCid[peer], hdr);
}

static void DynamicCongestion(size_t peer, bool congested) {
  if (peer >= kMaxPeers || s_DynCid[peer] == 0 || !appl_info.pL2CA_CongestionStatus_Cb) return;
  appl_info.pL2CA_CongestionStatus_Cb(s_DynCid[peer], congested);
}

static void DynamicError(size_t peer, FuzzedDataProvider& fdp) {
  if (peer >= kMaxPeers || s_DynCid[peer] == 0 || !appl_info.pL2CA_Error_Cb) return;
  appl_info.pL2CA_Error_Cb(s_DynCid[peer], fdp.ConsumeIntegral<uint16_t>());
}

static size_t PickPeer(FuzzedDataProvider& fdp, size_t num_peers) {
  if (num_peers == 0) return 0;
  return fdp.ConsumeIntegralInRange<size_t>(0, num_peers - 1);
}

static void ScriptDiscoveryFlow(size_t peer, FuzzedDataProvider& fdp, bool dyn = false) {
  auto send = [&](const std::vector<uint8_t>& pdu) {
    dyn ? FeedDynamicPeerPacket(peer, pdu) : FeedFixedPeerPacket(peer, pdu);
  };

  send(AttExchangeMtu(fdp, false));
  send(AttReadByGroupTypeReq(fdp));
  send(AttFindInfoReq(fdp));
  send(AttReadByTypeReq(fdp));
  send(AttReadReq(fdp, false));
  send(AttReadReq(fdp, true));
}

static void ScriptWriteFlow(size_t peer, FuzzedDataProvider& fdp, bool dyn = false) {
  auto send = [&](const std::vector<uint8_t>& pdu) {
    dyn ? FeedDynamicPeerPacket(peer, pdu) : FeedFixedPeerPacket(peer, pdu);
  };

  send(AttWriteReq(fdp, GATT_CMD_WRITE));
  send(AttWriteReq(fdp, GATT_REQ_WRITE));
  send(AttPrepareWriteReq(fdp));
  send(AttPrepareWriteReq(fdp));
  send(AttExecuteWriteReq(fdp));
}

static void ScriptReadMultiFlow(size_t peer, FuzzedDataProvider& fdp, bool dyn = false) {
  auto send = [&](const std::vector<uint8_t>& pdu) {
    dyn ? FeedDynamicPeerPacket(peer, pdu) : FeedFixedPeerPacket(peer, pdu);
  };

  send(AttReadMultiReq(fdp, false));
  send(AttReadMultiReq(fdp, true));
  send(AttHandleValueConfirmation());
}

static void ClientInit(bool eatt_support, size_t num_peers) {
  GattInit(eatt_support);

  for (size_t i = 0; i < num_peers && i < kMaxPeers; i++) {
    (void)GATT_Connect(s_AppIf, kPeerAddrs[i], BTM_BLE_DIRECT_CONNECTION, BT_TRANSPORT_LE, false);
    ConnectPeer(i);
  }
}

static void ClientCleanup(size_t num_peers) {
  for (size_t i = 0; i < num_peers && i < kMaxPeers; i++) {
    (void)GATT_CancelConnect(s_AppIf, kPeerAddrs[i], true);
    DisconnectPeer(i);
  }

  CleanupGatt();
}

static void DoClientOperation(FuzzedDataProvider& fdp, size_t peer) {
  uint16_t conn_id = GetConnId(peer);
  if (conn_id == 0) return;



  switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 13)) {
    case 0: {
      uint16_t mtu = fdp.ConsumeIntegralInRange<uint16_t>(0, GATT_MAX_MTU_SIZE + 256);
      (void)GATTC_ConfigureMTU(conn_id, mtu);
      break;
    }
    case 1: { // discovery

      uint16_t start =
          PickHandle(fdp);

      uint16_t end =
          fdp.ConsumeBool()
              ? PickHandle(fdp)
              : 0xffff;

      auto type =
          static_cast<tGATT_DISC_TYPE>(
              fdp.ConsumeIntegralInRange<uint8_t>(
                  GATT_DISC_SRVC_ALL,
                  GATT_DISC_MAX-1));

      if (fdp.ConsumeBool())
      {
          (void)GATTC_Discover(
              conn_id,
              type,
              start,
              end,
              Uuid::From16Bit(
                  PickUuid16(fdp)));
      }
      else
      {
          (void)GATTC_Discover(
              conn_id,
              type,
              start,
              end);
      }

      break;
    }

    case 2: { // read

      tGATT_READ_PARAM rp{};
      memset(&rp, 0, sizeof(rp));

      switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 4)) {

        case 0: { // READ_BY_HANDLE
          rp.by_handle.auth_req = GATT_AUTH_REQ_NONE;
          rp.by_handle.handle = PickHandle(fdp);

          (void)GATTC_Read(
              conn_id,
              GATT_READ_BY_HANDLE,
              &rp);
          break;
        }

        case 1: { // READ_BY_TYPE
          rp.char_type.auth_req = GATT_AUTH_REQ_NONE;
          rp.char_type.s_handle = PickHandle(fdp);
          rp.char_type.e_handle =
              fdp.ConsumeBool()
                  ? PickHandle(fdp)
                  : 0xffff;

          rp.char_type.uuid =
              Uuid::From16Bit(PickUuid16(fdp));

          (void)GATTC_Read(
              conn_id,
              GATT_READ_BY_TYPE,
              &rp);
          break;
        }

        case 2: { // READ_PARTIAL
          rp.partial.auth_req = GATT_AUTH_REQ_NONE;
          rp.partial.handle = PickHandle(fdp);
          rp.partial.offset =
              fdp.ConsumeIntegral<uint16_t>();

          (void)GATTC_Read(
              conn_id,
              GATT_READ_PARTIAL,
              &rp);
          break;
        }

        case 3:
        case 4: { // READ_MULTIPLE

          rp.read_multiple.auth_req =
              GATT_AUTH_REQ_NONE;

          rp.read_multiple.variable_len =
              fdp.ConsumeBool();

          rp.read_multiple.num_handles =
              fdp.ConsumeIntegralInRange<uint16_t>(
                  1,
                  GATT_MAX_READ_MULTI_HANDLES);

          for (uint16_t i = 0;
               i < rp.read_multiple.num_handles;
               i++) {
            rp.read_multiple.handles[i] =
                PickHandle(fdp);
          }

          (void)GATTC_Read(
              conn_id,
              rp.read_multiple.variable_len
                  ? GATT_READ_MULTIPLE_VAR_LEN
                  : GATT_READ_MULTIPLE,
              &rp);

          break;
        }
      }

      break;
    }
    /*
    case 3: {
      tGATT_VALUE value{};
      value.handle = PickHandle(fdp);
      value.len = fdp.ConsumeIntegralInRange<uint16_t>(0, 64);
      auto bytes = fdp.ConsumeBytes<uint8_t>(value.len);
      value.len = std::min<uint16_t>(value.len, bytes.size());
      memcpy(value.value, bytes.data(), value.len);
      (void)GATTC_Write(conn_id, GATT_WRITE, &value);
      break;
    }
    */



    /*
    case 3: { // write

      tGATT_VALUE value{};
      value.handle = PickHandle(fdp);

      value.offset =
          fdp.ConsumeIntegral<uint16_t>();

      value.auth_req =
          GATT_AUTH_REQ_NONE;

      value.len =
          fdp.ConsumeIntegralInRange<uint16_t>(
              0,
              64);

      auto bytes =
          fdp.ConsumeBytes<uint8_t>(
              value.len);

      value.len =
          std::min<uint16_t>(
              value.len,
              bytes.size());

      memcpy(
          value.value,
          bytes.data(),
          value.len);

      tGATT_WRITE_TYPE type;

      switch(
          fdp.ConsumeIntegralInRange<uint8_t>(0,2))
      {
          case 0:
              type = GATT_WRITE;
              break;

          case 1:
              type = GATT_WRITE_NO_RSP;
              break;

          case 2:
          default:
              type = GATT_WRITE_PREPARE;
              break;
      }

      (void)GATTC_Write(
          conn_id,
          type,
          &value);

      break;
    }
    */


    case 3: { // write
      tGATT_VALUE value{};

      value.handle = PickHandle(fdp);
      value.auth_req = GATT_AUTH_REQ_NONE;

      value.len = fdp.ConsumeIntegralInRange<uint16_t>(0, 128);
      auto bytes = fdp.ConsumeBytes<uint8_t>(value.len);

      value.len = std::min<uint16_t>(value.len, bytes.size());
      value.len = std::min<uint16_t>(value.len, GATT_MAX_ATTR_LEN);

      memcpy(value.value, bytes.data(), value.len);

      tGATT_WRITE_TYPE type;
      switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 2)) {
        case 0:
          type = GATT_WRITE;
          value.offset = 0;
          break;

        case 1:
          type = GATT_WRITE_NO_RSP;
          value.offset = 0;
          break;

        case 2:
        default:
          type = GATT_WRITE_PREPARE;
          value.offset = 0;  // important: do not randomize this
          break;
      }

      (void)GATTC_Write(conn_id, type, &value);
      break;
    }

    case 4: {
      (void)GATTC_SendHandleValueConfirm(conn_id, PickHandle(fdp));
      break;
    }
    case 5: {
      FixedCongestion(peer, true);
      FixedCongestion(peer, false);
      break;
    }
    /*
    case 6: {
      DisconnectPeer(peer);
      ConnectPeer(peer);
      break;
    }
    */

    case 6: { // lifecycle exercise

      switch(
          fdp.ConsumeIntegralInRange<uint8_t>(0,5))
      {
          case 0:
          {
              // normal connection path
              ConnectPeer(peer);
              break;
          }

          case 1:
          {
              // reconnect path
              DisconnectPeer(peer);

              ConnectPeer(peer);

              DoClientOperation(
                  fdp,
                  peer);

              break;
          }

          case 2:
          {
              // force disconnect path
              (void)GATT_Disconnect(
                  conn_id);

              DisconnectPeer(
                  peer);

              break;
          }

          case 3:
          {
              // repeated connect
              ConnectPeer(peer);
              ConnectPeer(peer);
              ConnectPeer(peer);

              break;
          }

          case 4:
          {
              // disconnect while active request exists

              tGATT_READ_PARAM rp{};
              rp.by_handle.handle=
                  PickHandle(fdp);

              (void)GATTC_Read(
                  conn_id,
                  GATT_READ_BY_HANDLE,
                  &rp);

              DisconnectPeer(peer);

              break;
          }

          case 5:
          {
              // connect → dynamic connect → disconnect

              ConnectPeer(peer);

              DynamicConnectPeer(
                  peer,
                  fdp);

              DynamicDisconnectPeer(
                  peer,
                  false);

              DisconnectPeer(peer);

              break;
          }
      }

      break;
    }

    case 7: {
      FeedFixedPeerPacket(peer, RandomOrStructuredPdu(fdp));
      break;
    }
    case 8: {
      DynamicConnectPeer(peer, fdp);
      FeedDynamicPeerPacket(peer, RandomOrStructuredPdu(fdp));
      DynamicDisconnectPeer(peer, fdp.ConsumeBool());
      break;
    }
    case 9: { // service change indication
        /*
        (void)GATTC_SendServiceChangeIndication(
            conn_id);
        */
        break;
    }

    case 10: { // dynamic congestion
        DynamicCongestion(
            peer,
            fdp.ConsumeBool());
        break;
    }

    case 11: { // dynamic error
        DynamicError(
            peer,
            fdp);
        break;
    }

    case 12: { // scripted flow

        switch(
            fdp.ConsumeIntegralInRange<uint8_t>(0,2))
        {
            case 0:
                ScriptDiscoveryFlow(
                    peer,
                    fdp,
                    false);
                break;

            case 1:
                ScriptWriteFlow(
                    peer,
                    fdp,
                    false);
                break;

            case 2:
                ScriptReadMultiFlow(
                    peer,
                    fdp,
                    false);
                break;
        }

        break;
    }
    case 13: {
      (void)GATT_Disconnect(conn_id);
      break;
    }

  }
}

static void FuzzAsServer(FuzzedDataProvider& fdp) {
  bool eatt_support = fdp.ConsumeBool();
  ServerInit(eatt_support);

  size_t num_peers = fdp.ConsumeIntegralInRange<size_t>(1, kMaxPeers);

  for (size_t i = 0; i < num_peers; i++) {
    if (fdp.ConsumeBool()) ConnectPeer(i);
    if (fdp.ConsumeBool()) DynamicConnectPeer(i, fdp);
  }

  while (fdp.remaining_bytes() > 0) {
    size_t peer = PickPeer(fdp, num_peers);
    uint8_t action = fdp.ConsumeIntegralInRange<uint8_t>(0, 17);

    switch (action) {
      case 0:
        ConnectPeer(peer);
        break;
      case 1:
        DisconnectPeer(peer, BT_TRANSPORT_LE, fdp.ConsumeIntegral<uint16_t>());
        break;
      case 2:
        DisconnectPeer(peer);
        ConnectPeer(peer);
        break;
      case 3:
        FixedCongestion(peer, fdp.ConsumeBool());
        break;
      case 4:
        FeedFixedPeerPacket(peer, RandomOrStructuredPdu(fdp));
        break;
      case 5:
        ScriptDiscoveryFlow(peer, fdp, false);
        break;
      case 6:
        ScriptWriteFlow(peer, fdp, false);
        break;
      case 7:
        ScriptReadMultiFlow(peer, fdp, false);
        break;
      case 8: {
        auto size = fdp.ConsumeIntegralInRange<uint16_t>(0, kMaxPacketSize);
        FeedFixedPeerPacket(peer, fdp.ConsumeBytes<uint8_t>(size));
        break;
      }
      case 9:
        DynamicConnectPeer(peer, fdp);
        break;
      case 10:
        DynamicDisconnectPeer(peer, fdp.ConsumeBool());
        break;
      case 11:
        DynamicCongestion(peer, fdp.ConsumeBool());
        break;
      case 12:
        DynamicError(peer, fdp);
        break;
      case 13:
        FeedDynamicPeerPacket(peer, RandomOrStructuredPdu(fdp));
        break;
      case 14:
        ScriptDiscoveryFlow(peer, fdp, true);
        break;
      case 15:
        ScriptWriteFlow(peer, fdp, true);
        break;
      case 16:
        ScriptReadMultiFlow(peer, fdp, true);
        break;
      case 17:
      default:
        DoClientOperation(fdp, peer);
        break;
    }
  }

  for (size_t i = 0; i < num_peers; i++) {
    if (fdp.ConsumeBool()) DynamicDisconnectPeer(i, fdp.ConsumeBool());
    if (fdp.ConsumeBool()) DisconnectPeer(i);
  }

  CleanupGatt();
}

static void FuzzAsClient(FuzzedDataProvider& fdp) {
  bool eatt_support = fdp.ConsumeBool();
  size_t num_peers = fdp.ConsumeIntegralInRange<size_t>(1, kMaxPeers);
  ClientInit(eatt_support, num_peers);

  while (fdp.remaining_bytes() > 0) {
    size_t peer = PickPeer(fdp, num_peers);
    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 9)) {
      case 0:
        DoClientOperation(fdp, peer);
        break;
      case 1:
        FeedFixedPeerPacket(peer, AttExchangeMtu(fdp, true));
        break;
      case 2:
        FeedFixedPeerPacket(peer, RandomOrStructuredPdu(fdp));
        break;
      case 3:
        FixedCongestion(peer, fdp.ConsumeBool());
        break;
      case 4:
        DisconnectPeer(peer);
        break;
      case 5:
        ConnectPeer(peer);
        break;
      case 6:
        DynamicConnectPeer(peer, fdp);
        break;
      case 7:
        FeedDynamicPeerPacket(peer, RandomOrStructuredPdu(fdp));
        break;
      case 8:
        DynamicDisconnectPeer(peer, fdp.ConsumeBool());
        break;
      case 9:
      {
          ConnectPeer(peer);

          FixedCongestion(
              peer,
              true);

          FixedCongestion(
              peer,
              false);

          (void)GATT_Disconnect(
              GetConnId(peer));

          break;
      }
    }
  }

  ClientCleanup(num_peers);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;

  // static Fakes* fakes = new Fakes();
  // (void)fakes;

  static Fakes fakes;

  FuzzedDataProvider fdp(data, size);

  // Split modes so corpus can specialize instead of one huge ambiguous loop.
  switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 3)) {
    case 0:
      FuzzAsServer(fdp);
      break;
    case 1:
      FuzzAsClient(fdp);
      break;
    case 2:
      FuzzAsServer(fdp);
      break;
    case 3:
    default:
      FuzzAsClient(fdp);
      break;
  }

  return 0;
}
