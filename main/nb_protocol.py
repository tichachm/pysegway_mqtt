"""
nb_protocol.py — Ninebot BLE Encryption2 frame builder/parser.

Frame format (Encryption2, header 0x5A 0xB5):

  App → Device (plaintext before encrypt):
    [0x5A, 0xB5, LEN, 0x3E, target_board, cmd, index, data...]
    LEN = len(data)

  Device → App (plaintext after decrypt):
    [0x5A, 0xB5, LEN, source_board, 0x3E, cmd, index, data...]

  On the wire (after encrypt):
    [0x5A, 0xB5, LEN, ...ciphertext..., tag(4), counter(2)]
    Total = LEN + 13 bytes
"""

import struct
from dataclasses import dataclass
from enum import Enum


# ---------------------------------------------------------------------------
# Protocol generation
# ---------------------------------------------------------------------------

class ProtocolGen(Enum):
    GEN2 = "gen2"  # 0x5AA5 — E125S and older devices
    GEN3 = "gen3"  # 0x5AB5 — newer devices


# Protocol constants
SYNC1 = 0x5A
SYNC2_GEN2 = 0xA5
SYNC2_GEN3 = 0xB5
VALID_SYNC2 = {SYNC2_GEN2, SYNC2_GEN3}
BT_ID = 0x3E

# Per-generation config
PROTO_CONFIG = {
    ProtocolGen.GEN2: {"sync2": SYNC2_GEN2, "vehicle_target": 0x09, "vehicle_cmd": 0x64},
    ProtocolGen.GEN3: {"sync2": SYNC2_GEN3, "vehicle_target": 0x04, "vehicle_cmd": 0x03},
}

# Command types
CMD_READ = 0x01
CMD_WRITE = 0x02
CMD_WRITE_NR = 0x03
CMD_READ_RESP = 0x04
CMD_WRITE_RESP = 0x05

# Handshake commands
CMD_PRE_COMM = 0x5B  # 91
CMD_SET_PWD = 0x5C   # 92
CMD_AUTH = 0x5D       # 93

# Board IDs (sendId)
BOARD_DIS = 0x01   # Display / Dashboard
BOARD_BLE = 0x04   # BLE module (handshake target)
BOARD_VCU = 0x09   # Vehicle Control Unit (Gen2 vehicle actions)
BOARD_CTRL = 0x20  # Main controller

# Vehicle action registers (Gen2 cmd=0x64 with $ident payload)
REG_OPEN_ACC = 0x4E   # Power on / open accelerator
REG_CLOSE_ACC = 0x46  # Power off / close accelerator
REG_OPEN_TRUNK = 0x73 # Open seat / trunk

# DIS dashboard registers (target 0x01) — from capture polling loop
REG_SN = 0x10              # rSN — 14-byte ASCII serial number
REG_ALARM = 0x1C           # rAlarm — alarm flags (2B)
REG_SIG_MAX_SPEED = 0x24   # rSigMaxSpeed (2B)
REG_LEFT_MILEAGE = 0x25    # rLeftMileage — remaining range km (2B)
REG_SPEED = 0x26           # rSpeed — current speed (2B, 0.1 km/h units)
REG_AVE_SPEED = 0x27       # rAveSpeed — average speed (2B)
REG_TIME_FULL = 0x39       # rTimeFull — time until full charge (2B, 65535=N/A)
REG_RATED_SPEED = 0x48     # rRatedSpeed/rMaxSpeed (2B)
REG_WARN = 0x75            # rWarn/setWarn — 2B: LOW byte = prompt volume 0-100,
                           #                        HIGH byte = sound preset (0=Sound1, 1=Sound2, 2=Sound3)
REG_ALARM_VOLUME = 0x76    # rAlarmVolume — 0-100 (2B)
REG_ALARM_LEVEL = 0x77     # rAlarmLevel — alarm sensitivity enum (2B):
                           #               1=Sensitive, 2=High, 3=Standard, 4=Low
REG_LIGHT_LEVEL = 0x7B     # rLightLevel (2B)
REG_CTL_BOOL2 = 0x7C       # rCTLBool2 — control switches 2 (2B)
REG_FUN_BOOL = 0x7D        # rFunBool/setFunBool — function switches (2B)
REG_CTL_BOOL = 0x84        # rCTLBool/setCTLBool — control switches (2B)
REG_AUTO_LOCK = 0x85       # rAutoLock/setAutoLock (2B)
REG_FUN_APP_BOOL = 0x8A    # rFunAppBool — feature gate flags (2B)
REG_FUN_APP_BOOL2 = 0x8C   # rFunAppBool2 — feature gate flags 2 (2B)
REG_LIMIT_SPEED = 0x93     # rLimitSpeed — speed limit (2B)
REG_PRECISE_MILEAGE = 0xAF # rPreciseMileage (2B)
REG_BOOL = 0xB2            # rBool — vehicle status flags (2B)
REG_BOOL2 = 0xAA           # rBool2/setBool2 — riding-mode bitmask (2B):
                           #   bit 0=ECO, 1=Coast, 2=Furious, 3=M1 custom, 4=M2 custom
REG_BATTERY = 0xB5         # rBattery — battery percent (2B)
REG_MILEAGE = 0xB7         # rMileage — total odometer, meters unit (4B u32, × 0.001 = km)
REG_SINGLE_MILEAGE = 0xB9  # rSingleMileage — trip odometer, 10m unit (2B u16, × 0.01 = km)
REG_RUNNING_TIME = 0xBA    # rRunningTime — trip duration seconds (2B u16)
REG_POWER = 0xBD           # rPower — current power draw watts (2B int16 — signed; regen is negative)

# DIS version registers
REG_DIS_VERSION = 0x1A     # rDisVersion (2B)
REG_MCU_VERSION = 0x28     # rMCUVersion (2B)
REG_BMS1_VERSION = 0x30    # rBms1Version (2B)
REG_BMS2_VERSION = 0x31    # rBms2Version (2B)
REG_ECU_VERSION = 0x4C     # rEcuVersion (2B)
REG_CFG_MODE = 0x74        # rCfgMode (2B)

# VCU registers (target 0x09)
REG_MAIN_POWER = 0x03      # rMainPower — power state (2B)
REG_ECU_PN = 0x28          # rECUPN — ECU part number (14B)
REG_STATE_BOOL = 0x52      # rStateBool (2B)

# BLE registers (target 0x04)
REG_BLE_VERSION = 0x68     # rBleVersion (2B)
REG_FUN_SUP_BOOL = 0x50    # rFunSupBool — supported features (6B)

# MCU registers (target 0x20)
BOARD_MCU = 0x20
REG_MCU_MAX_SPEED = 0x09   # rMCUMaxSpeed — firmware absolute max (2B, read-only)
REG_GEAR_DATA1 = 0x22      # rGearData1 — 32-byte gear profile (read/write)
REG_GEAR_ENERGY = 0x2C     # setGearEnergy — motor recovery 20/40/60/80/100 (2B)
REG_GEAR_ACC_SPEED = 0x2D  # setGearAccSpeed — acceleration speed limit 0-100 (2B)
REG_GEAR_ACC_SENS = 0x2E   # setGearAccSensitivity — 0=low/1=moderate/2=high (2B)
REG_GEAR_TCS = 0x2F        # setGearTcs — 0=off/1=moderate/2=strongest (2B)
REG_GEAR_NITRO = 0x30      # setGearNitroSpeed — 0=off/1=on (2B)
REG_GEAR_TOP_SPEED = 0x31  # setGearTopSpeed — per-mode max 15-140 km/h (2B)
REG_GEAR_DATA2 = 0x3A      # rGearData2 — secondary 32-byte gear profile
REG_SPEED_INTENSITY = 0x52 # rSpeedIntensity (2B)
REG_SPEED_SAFE_LOCK = 0x53 # rSpeedSafeLock — MCU-level speed cap (2B, gated MOLE)
REG_TCS = 0x55             # rTCS — traction control (2B)
REG_SLOPE = 0x56           # rSlope (2B)
REG_ELE_BRAKE = 0x57       # rEleBrake — electronic brake (2B)

# BMS registers (target 0x22/0x23)
BOARD_BMS1 = 0x22
BOARD_BMS2 = 0x23
REG_VOLTAGE = 0x1A         # rVoltage (2B, 0.01V units)
REG_BMS_CYCLE_COUNT = 0x1B # rBmsCycleCount (2B)
REG_BMS_SOC = 0x32         # rBmsSOC — state of charge (2B)

# HEP registers (target 0x28) — headlight/taillight
BOARD_HEP = 0x28
REG_HEP_LIGHT = 0x0E       # rHepLight/setHepLight


@dataclass
class NbFrame:
    """Parsed Ninebot frame (after decryption)."""
    length: int     # LEN field (data bytes count)
    board_id: int   # Source board (byte 3 in response)
    cmd: int        # Command byte
    index: int      # Index / status byte
    data: bytes     # Payload data


def build_frame(target: int, cmd: int, index: int, data: bytes = b"",
                gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """
    Build a plaintext Encryption2 frame (App → Device).

    Returns: [0x5A, sync2, len(data), 0x3E, target, cmd, index, data...]
    """
    length = len(data)
    if length > 255:
        raise ValueError(f"Data too long: {length} > 255")
    sync2 = PROTO_CONFIG[gen]["sync2"]
    header = bytes([SYNC1, sync2, length, BT_ID, target, cmd, index])
    return header + data


def parse_frame(decrypted: bytes) -> NbFrame | None:
    """
    Parse a decrypted frame (Device → App).

    Expected layout: [0x5A, sync2, LEN, source_board, 0x3E, cmd, index, data...]
    Accepts both Gen2 (0xA5) and Gen3 (0xB5) sync bytes.
    """
    if len(decrypted) < 7:
        return None
    if decrypted[0] != SYNC1 or decrypted[1] not in VALID_SYNC2:
        return None
    if decrypted[4] != BT_ID:
        # BT_ID check (byte 4 in response must be 0x3E)
        return None

    length = decrypted[2]
    board_id = decrypted[3]
    cmd = decrypted[5]
    index = decrypted[6]
    data = decrypted[7 : 7 + length]

    return NbFrame(length=length, board_id=board_id, cmd=cmd, index=index, data=data)


def frame_hex(data: bytes) -> str:
    """Format bytes as hex string for logging."""
    return " ".join(f"{b:02X}" for b in data)


# ---------------------------------------------------------------------------
# Convenience builders for specific commands
# ---------------------------------------------------------------------------

def build_pre_comm(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """PRE_COMM request: empty payload to BLE board."""
    return build_frame(BOARD_BLE, CMD_PRE_COMM, 0x00, gen=gen)


def build_set_pwd(password: bytes, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """SET_PWD request: send 16-byte password to BLE board."""
    return build_frame(BOARD_BLE, CMD_SET_PWD, 0x00, password[:16], gen=gen)


def build_auth(sn: bytes, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """AUTH request: send 14-byte SN to BLE board."""
    return build_frame(BOARD_BLE, CMD_AUTH, 0x00, sn[:14], gen=gen)


def build_read(target: int, register: int, read_len: int = 2,
               gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Generic READ request: cmd=READ, data=[read_len]."""
    return build_frame(target, CMD_READ, register, bytes([read_len]), gen=gen)


def build_write_nr(target: int, register: int, data: bytes,
                   gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Generic WRITE_NR request (no response expected)."""
    return build_frame(target, CMD_WRITE_NR, register, data, gen=gen)


# ---------------------------------------------------------------------------
# Dashboard reads — matching the capture polling loop
# ---------------------------------------------------------------------------

def build_read_sn(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read serial number (14 bytes) from DIS."""
    return build_read(BOARD_DIS, REG_SN, 14, gen=gen)


def build_read_battery(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read battery percentage from DIS."""
    return build_read(BOARD_DIS, REG_BATTERY, 2, gen=gen)


def build_read_speed_live(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read current speed from DIS (0.1 km/h units)."""
    return build_read(BOARD_DIS, REG_SPEED, 2, gen=gen)


def build_read_left_mileage(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read remaining range (km) from DIS."""
    return build_read(BOARD_DIS, REG_LEFT_MILEAGE, 2, gen=gen)


def build_read_mileage(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read total odometer (4 bytes) from DIS."""
    return build_read(BOARD_DIS, REG_MILEAGE, 4, gen=gen)


def build_read_running_time(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read trip duration (2 bytes, seconds) from DIS."""
    return build_read(BOARD_DIS, REG_RUNNING_TIME, 2, gen=gen)


def build_read_single_mileage(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read trip odometer (2 bytes u16, 10m unit → × 0.01 km) from DIS."""
    return build_read(BOARD_DIS, REG_SINGLE_MILEAGE, 2, gen=gen)


def build_read_sig_max_speed(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read trip max speed (2 bytes u16, 0.1 km/h units) from DIS."""
    return build_read(BOARD_DIS, REG_SIG_MAX_SPEED, 2, gen=gen)


def build_read_ave_speed(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read trip average speed (2 bytes u16, 0.1 km/h units) from DIS."""
    return build_read(BOARD_DIS, REG_AVE_SPEED, 2, gen=gen)


def build_read_alarm(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read alarm flags from DIS."""
    return build_read(BOARD_DIS, REG_ALARM, 2, gen=gen)


def build_read_rated_speed(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read rated/max speed from DIS."""
    return build_read(BOARD_DIS, REG_RATED_SPEED, 2, gen=gen)


def build_read_power(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read current power draw from DIS."""
    return build_read(BOARD_DIS, REG_POWER, 2, gen=gen)


def build_read_speed_limit(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read speed limit from DIS."""
    return build_read(BOARD_DIS, REG_LIMIT_SPEED, 2, gen=gen)


def build_read_bool(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read vehicle status flags from DIS (0xB2). Capture: 2882→2881 after power-on."""
    return build_read(BOARD_DIS, REG_BOOL, 2, gen=gen)


def build_read_time_full(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read time until full charge from DIS (0x39). 65535 = N/A."""
    return build_read(BOARD_DIS, REG_TIME_FULL, 2, gen=gen)


def build_read_precise_mileage(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read precise mileage from DIS (0xAF)."""
    return build_read(BOARD_DIS, REG_PRECISE_MILEAGE, 2, gen=gen)


def build_read_fun_bool(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read function switches from DIS (0x7D). Capture: 29742."""
    return build_read(BOARD_DIS, REG_FUN_BOOL, 2, gen=gen)


def build_read_ctl_bool2(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read control switches 2 from DIS (0x7C). Capture: 4."""
    return build_read(BOARD_DIS, REG_CTL_BOOL2, 2, gen=gen)


def build_read_warn(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read warning/sound preset from DIS (0x75). Capture: 20/276."""
    return build_read(BOARD_DIS, REG_WARN, 2, gen=gen)


# VCU reads (target 0x09)
def build_read_main_power(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read main power state from VCU (0x03). Capture: 503=off, 511=on."""
    return build_read(BOARD_VCU, REG_MAIN_POWER, 2, gen=gen)


def build_read_ecu_pn(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read ECU part number from VCU (14 bytes)."""
    return build_read(BOARD_VCU, REG_ECU_PN, 14, gen=gen)


# BLE reads
def build_read_fun_sup_bool(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read supported features from BLE (0x50, 6 bytes). Capture: 000000000000."""
    return build_read(BOARD_BLE, REG_FUN_SUP_BOOL, 6, gen=gen)


# Version reads
def build_read_dis_version(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    return build_read(BOARD_DIS, REG_DIS_VERSION, 2, gen=gen)

def build_read_mcu_version(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    return build_read(BOARD_DIS, REG_MCU_VERSION, 2, gen=gen)

def build_read_ble_version(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    return build_read(BOARD_BLE, REG_BLE_VERSION, 2, gen=gen)

def build_read_ecu_version(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    return build_read(BOARD_DIS, REG_ECU_VERSION, 2, gen=gen)

def build_read_bms1_version(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    return build_read(BOARD_DIS, REG_BMS1_VERSION, 2, gen=gen)


# Feature flags
def build_read_fun_app_bool(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    return build_read(BOARD_DIS, REG_FUN_APP_BOOL, 2, gen=gen)

def build_read_cfg_mode(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    return build_read(BOARD_DIS, REG_CFG_MODE, 2, gen=gen)


# BMS reads
def build_read_voltage(bms: int = BOARD_BMS1, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read battery voltage (0.01V units)."""
    return build_read(bms, REG_VOLTAGE, 2, gen=gen)

def build_read_bms_soc(bms: int = BOARD_BMS1, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read BMS state of charge."""
    return build_read(bms, REG_BMS_SOC, 2, gen=gen)

def build_read_cycle_count(bms: int = BOARD_BMS1, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read BMS charge cycle count."""
    return build_read(bms, REG_BMS_CYCLE_COUNT, 2, gen=gen)


# ---------------------------------------------------------------------------
# rWarn (DIS 0x75) helpers — 16-bit split
# ---------------------------------------------------------------------------

def pack_warn(volume: int, preset: int) -> int:
    """Pack rWarn u16 from its two fields. LOW=volume 0-100, HIGH=preset 0-2."""
    return ((preset & 0xFF) << 8) | (volume & 0xFF)


def warn_volume(warn: int) -> int:
    return warn & 0xFF


def warn_preset(warn: int) -> int:
    return (warn >> 8) & 0xFF


# ---------------------------------------------------------------------------
# Settings writes
# ---------------------------------------------------------------------------

def build_set_warn(value: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set rWarn (DIS:0x75) u16: LOW byte=volume 0-100, HIGH byte=sound preset 0-2.
    Use pack_warn(volume, preset) to compose the value.
    """
    data = struct.pack("<H", value)
    return build_write_nr(BOARD_DIS, REG_WARN, data, gen=gen)


def build_read_alarm_volume(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read alarm volume (DIS:0x76, 0-100)."""
    return build_read(BOARD_DIS, REG_ALARM_VOLUME, 2, gen=gen)


def build_set_alarm_volume(value: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set alarm volume (DIS:0x76, 0-100)."""
    data = struct.pack("<H", value)
    return build_write_nr(BOARD_DIS, REG_ALARM_VOLUME, data, gen=gen)


def build_read_alarm_level(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read alarm sensitivity (DIS:0x77). 1=Sensitive, 2=High, 3=Standard, 4=Low."""
    return build_read(BOARD_DIS, REG_ALARM_LEVEL, 2, gen=gen)


def build_set_alarm_level(level: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set alarm sensitivity (DIS:0x77). 1=Sensitive, 2=High, 3=Standard, 4=Low."""
    data = struct.pack("<H", level)
    return build_write_nr(BOARD_DIS, REG_ALARM_LEVEL, data, gen=gen)


def build_read_auto_lock(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read auto-lock timer seconds (DIS:0x85)."""
    return build_read(BOARD_DIS, REG_AUTO_LOCK, 2, gen=gen)


def build_set_auto_lock(seconds: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set auto-lock timer seconds (DIS:0x85)."""
    data = struct.pack("<H", seconds)
    return build_write_nr(BOARD_DIS, REG_AUTO_LOCK, data, gen=gen)


def build_read_bool2(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read riding-mode bitmask (DIS:0xAA). Bits: 0=ECO, 1=Coast, 2=Furious, 3=M1, 4=M2."""
    return build_read(BOARD_DIS, REG_BOOL2, 2, gen=gen)


def build_set_bool2(mask: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Write riding-mode bitmask (DIS:0xAA). Bits: 0=ECO, 1=Coast, 2=Furious, 3=M1, 4=M2."""
    data = struct.pack("<H", mask)
    return build_write_nr(BOARD_DIS, REG_BOOL2, data, gen=gen)


# MCU-level "firmware internal" settings — not user-facing in the official
# E-series app but still writable for experimentation.
def build_read_tcs(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read MCU TCS level (MCU:0x55). Global TCS on/off is rCTLBool2 bit 13 reversed."""
    return build_read(BOARD_MCU, REG_TCS, 2, gen=gen)


def build_set_tcs(level: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set MCU TCS level (MCU:0x55, 0/1/2)."""
    data = struct.pack("<H", level)
    return build_write_nr(BOARD_MCU, REG_TCS, data, gen=gen)


def build_read_slope(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    return build_read(BOARD_MCU, REG_SLOPE, 2, gen=gen)


def build_set_slope(mode: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    data = struct.pack("<H", mode)
    return build_write_nr(BOARD_MCU, REG_SLOPE, data, gen=gen)


def build_read_ele_brake(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read MCU electric brake level. Global on/off is rCTLBool2 bit 10 reversed."""
    return build_read(BOARD_MCU, REG_ELE_BRAKE, 2, gen=gen)


def build_set_ele_brake(value: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    data = struct.pack("<H", value)
    return build_write_nr(BOARD_MCU, REG_ELE_BRAKE, data, gen=gen)


def build_set_cfg_mode(mode: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Select metric/imperial mode (DIS:0x74)."""
    data = struct.pack("<H", mode)
    return build_write_nr(BOARD_DIS, REG_CFG_MODE, data, gen=gen)


# ---------------------------------------------------------------------------
# One-shot actions — no payload
# ---------------------------------------------------------------------------

def build_play_sound(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Honk + flash lights. Spec: name=playSound, module=dis, s_cmd=0x11, ops=writeNR."""
    return build_frame(BOARD_DIS, 0x11, 0x00, b"", gen=gen)


def build_play_light(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Flash lights only (no sound). Spec: name=playLight, module=hep, s_cmd=0x11, s_index=1, ops=writeNR."""
    return build_frame(BOARD_HEP, 0x11, 0x01, b"", gen=gen)


# ---------------------------------------------------------------------------
# MCU gear profile reads & writes (target 0x20)
# ---------------------------------------------------------------------------

def build_read_gear_data(slot: int = 1, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read 32-byte gear profile from MCU. slot=1 (0x22) or 2 (0x3A)."""
    reg = REG_GEAR_DATA1 if slot == 1 else REG_GEAR_DATA2
    return build_read(BOARD_MCU, reg, 32, gen=gen)


def build_write_gear_data(data: bytes, slot: int = 1,
                          gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Write full 32-byte gear profile to MCU."""
    reg = REG_GEAR_DATA1 if slot == 1 else REG_GEAR_DATA2
    return build_write_nr(BOARD_MCU, reg, data[:32], gen=gen)


def build_read_gear_top_speed(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read gear top speed from MCU (0x31). Range: 15-140 km/h."""
    return build_read(BOARD_MCU, REG_GEAR_TOP_SPEED, 2, gen=gen)


def build_set_gear_top_speed(speed: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set per-mode max speed (MCU:0x31). Range: 15-140 km/h."""
    data = struct.pack("<H", speed)
    return build_write_nr(BOARD_MCU, REG_GEAR_TOP_SPEED, data, gen=gen)


def build_read_gear_acc_speed(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read acceleration speed limit from MCU (0x2D). Range: 0-100."""
    return build_read(BOARD_MCU, REG_GEAR_ACC_SPEED, 2, gen=gen)


def build_set_gear_acc_speed(value: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set acceleration speed limit (MCU:0x2D). Range: 0-100."""
    data = struct.pack("<H", value)
    return build_write_nr(BOARD_MCU, REG_GEAR_ACC_SPEED, data, gen=gen)


def build_set_gear_acc_sens(value: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set acceleration sensitivity (MCU:0x2E). 0=low, 1=moderate, 2=high."""
    data = struct.pack("<H", value)
    return build_write_nr(BOARD_MCU, REG_GEAR_ACC_SENS, data, gen=gen)


def build_set_gear_tcs(value: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set traction control (MCU:0x2F). 0=off, 1=moderate, 2=strongest."""
    data = struct.pack("<H", value)
    return build_write_nr(BOARD_MCU, REG_GEAR_TCS, data, gen=gen)


def build_set_gear_nitro(on: bool, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Enable/disable nitro speed boost (MCU:0x30). 0=off, 1=on."""
    data = struct.pack("<H", 1 if on else 0)
    return build_write_nr(BOARD_MCU, REG_GEAR_NITRO, data, gen=gen)


def build_set_gear_energy(value: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set motor energy recovery (MCU:0x2C). Values: 20/40/60/80/100."""
    data = struct.pack("<H", value)
    return build_write_nr(BOARD_MCU, REG_GEAR_ENERGY, data, gen=gen)


def build_read_mcu_max_speed(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read MCU absolute max speed (read-only, MCU:0x09)."""
    return build_read(BOARD_MCU, REG_MCU_MAX_SPEED, 2, gen=gen)


def build_read_speed_safe_lock(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read MCU speed safe lock (MCU:0x53). Gated by MOLE feature flag."""
    return build_read(BOARD_MCU, REG_SPEED_SAFE_LOCK, 2, gen=gen)


def build_set_speed_safe_lock(value: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Set MCU speed safe lock (MCU:0x53). Gated by MOLE feature flag."""
    data = struct.pack("<H", value)
    return build_write_nr(BOARD_MCU, REG_SPEED_SAFE_LOCK, data, gen=gen)


# Backward-compat aliases
def build_read_speed(gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Read speed limit from DIS board (alias for build_read_speed_limit)."""
    return build_read_speed_limit(gen=gen)


def build_write_speed(speed_kmh: int, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Write speed limit to DIS board: cmd=WRITE_NR, index=0x93, data=speed_le16."""
    data = struct.pack("<H", speed_kmh)
    return build_write_nr(BOARD_DIS, REG_LIMIT_SPEED, data, gen=gen)


# ---------------------------------------------------------------------------
# Vehicle action builders (Gen2: target=VCU cmd=0x64, Gen3: target=BLE cmd=0x03)
# ---------------------------------------------------------------------------

def _build_vehicle_action(register: int, ident: bytes,
                          gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Build a vehicle action frame with $ident payload."""
    cfg = PROTO_CONFIG[gen]
    return build_frame(cfg["vehicle_target"], cfg["vehicle_cmd"], register, ident, gen=gen)


def build_open_acc(ident: bytes, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Power on / open accelerator."""
    return _build_vehicle_action(REG_OPEN_ACC, ident, gen)


def build_close_acc(ident: bytes, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Power off / close accelerator."""
    return _build_vehicle_action(REG_CLOSE_ACC, ident, gen)


def build_open_trunk(ident: bytes, gen: ProtocolGen = ProtocolGen.GEN2) -> bytes:
    """Open seat / trunk compartment."""
    return _build_vehicle_action(REG_OPEN_TRUNK, ident, gen)
