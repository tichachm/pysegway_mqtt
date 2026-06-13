#!/usr/bin/env python3
"""
segway_ble_client.py — Modified Standalone BLE client for Segway/Ninebot vehicles.

Supports Gen2 (0x5AA5, E125S) and Gen3 (0x5AB5, newer) protocols.
Connects over BLE, completes 3-phase Encryption2 handshake,
reads/writes registers and sends vehicle actions.

"""

import argparse
import asyncio
import json
import logging
import os
import struct
import sys
import time

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice

from nb_crypto import FW_DATA, NbCrypto, generate_password
from nb_protocol import (
    BT_ID,
    BOARD_BLE,
    BOARD_BMS1,
    BOARD_BMS2,
    BOARD_DIS,
    BOARD_MCU,
    BOARD_VCU,
    CMD_AUTH,
    CMD_PRE_COMM,
    CMD_READ_RESP,
    CMD_SET_PWD,
    CMD_WRITE_RESP,
    NbFrame,
    ProtocolGen,
    VALID_SYNC2,
    build_auth,
    build_close_acc,
    build_open_acc,
    build_open_trunk,
    build_pre_comm,
    build_read,
    build_read_alarm,
    build_read_battery,
    build_read_ble_version,
    build_read_bms1_version,
    build_read_bms_soc,
    build_read_bool,
    build_read_cfg_mode,
    build_read_ctl_bool2,
    build_read_cycle_count,
    build_read_dis_version,
    build_read_ecu_pn,
    build_read_ecu_version,
    build_read_fun_app_bool,
    build_read_fun_bool,
    build_read_fun_sup_bool,
    build_read_left_mileage,
    build_read_main_power,
    build_read_mcu_version,
    build_read_mileage,
    build_read_power,
    build_read_precise_mileage,
    build_read_rated_speed,
    build_read_running_time,
    build_read_sn,
    build_read_speed,
    build_read_speed_live,
    build_read_time_full,
    build_read_voltage,
    build_read_warn,
    build_read_gear_data,
    build_read_gear_top_speed,
    build_read_gear_acc_speed,
    build_read_mcu_max_speed,
    build_read_speed_safe_lock,
    build_set_cfg_mode,
    build_set_gear_top_speed,
    build_set_gear_acc_speed,
    build_set_gear_acc_sens,
    build_set_gear_tcs,
    build_set_gear_nitro,
    build_set_gear_energy,
    build_set_pwd,
    build_set_speed_safe_lock,
    build_set_warn,
    build_read_single_mileage,
    build_read_sig_max_speed,
    build_read_ave_speed,
    build_read_alarm_volume,
    build_set_alarm_volume,
    build_read_alarm_level,
    build_set_alarm_level,
    build_read_auto_lock,
    build_set_auto_lock,
    build_read_bool2,
    build_set_bool2,
    build_play_sound,
    build_play_light,
    pack_warn,
    warn_volume,
    warn_preset,
    build_write_nr,
    build_write_speed,
    frame_hex,
    parse_frame,
)

log = logging.getLogger("segway")

# ---------------------------------------------------------------------------
# BLE UUIDs
# ---------------------------------------------------------------------------

# Ninebot Custom (primary — modern devices)
NB_SERVICE = "6e400001-0000-0000-006e-696e65626f74"
NB_WRITE   = "6e400002-0000-0000-006e-696e65626f74"
NB_NOTIFY  = "6e400004-0000-0000-006e-696e65626f74"

# Nordic UART (compatibility fallback)
NORDIC_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NORDIC_WRITE   = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NORDIC_NOTIFY  = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

# Standard GATT "Device Name" characteristic (0x2A00). On Segway/Ninebot
# scooters this returns the serial, which is the V2 encryption key (key1).
# The name is read from the device itself so a foreign serial can never be used.
GATT_DEVICE_NAME = "00002a00-0000-1000-8000-00805f9b34fb"

# Ninebot/Segway manufacturer-specific advertisement IDs. The encrypt-protocol
# version (2 = V2/supported, 3 = V3Auth/unsupported) is encoded in the payload.
# bleak may report the company id in either byte order, so check both.
NINEBOT_MFR_IDS = (20034, 20035, 16974, 16975)


# ---------------------------------------------------------------------------
# BLE transport
# ---------------------------------------------------------------------------

class BleTransport:
    """BLE transport with frame reassembly and async notification queue."""

    def __init__(self, client: BleakClient, write_uuid: str, notify_uuid: str):
        self.client = client
        self.write_uuid = write_uuid
        self.notify_uuid = notify_uuid
        self._rx_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._rx_buffer = bytearray()

    async def start(self):
        """Subscribe to notifications."""
        await self.client.start_notify(self.notify_uuid, self._on_notify)

    async def stop(self):
        """Unsubscribe from notifications."""
        try:
            await self.client.stop_notify(self.notify_uuid)
        except Exception:
            pass

    def _on_notify(self, _sender, data: bytearray):
        """Handle incoming BLE notification — reassemble frames."""
        self._rx_buffer.extend(data)
        self._try_extract_frame()

    def _try_extract_frame(self):
        """Try to extract a complete encrypted frame from the buffer."""
        buf = self._rx_buffer

        # Scan for sync bytes
        while len(buf) >= 3:
            # Find 0x5A followed by valid sync2 (0xA5 or 0xB5)
            idx = -1
            for i in range(len(buf) - 1):
                if buf[i] == 0x5A and buf[i + 1] in VALID_SYNC2:
                    idx = i
                    break
            if idx < 0:
                # No sync found, keep last byte in case it's 0x5A
                self._rx_buffer = buf[-1:] if buf and buf[-1] == 0x5A else bytearray()
                return
            if idx > 0:
                buf = buf[idx:]
                self._rx_buffer = buf

            if len(buf) < 3:
                return

            length = buf[2]
            total = length + 13  # encrypted frame size

            if len(buf) < total:
                return  # wait for more data

            frame = bytes(buf[:total])
            self._rx_buffer = buf[total:]
            buf = self._rx_buffer
            self._rx_queue.put_nowait(frame)

    async def send(self, data: bytes):
        """Write data to the TX characteristic, fragmenting at MTU boundary."""
        log.debug("TX (%d): %s", len(data), frame_hex(data))
        mtu_payload = self.client.mtu_size - 3  # ATT header overhead
        if mtu_payload < 20:
            mtu_payload = 20  # BLE 4.0 minimum
        for offset in range(0, len(data), mtu_payload):
            chunk = data[offset : offset + mtu_payload]
            await self.client.write_gatt_char(
                self.write_uuid, chunk, response=False)
            if offset + mtu_payload < len(data):
                await asyncio.sleep(0.01)  # small gap between fragments

    async def recv(self, timeout: float = 5.0) -> bytes:
        """Wait for a complete encrypted frame from notifications."""
        try:
            frame = await asyncio.wait_for(self._rx_queue.get(), timeout=timeout)
            log.debug("RX (%d): %s", len(frame), frame_hex(frame))
            return frame
        except asyncio.TimeoutError:
            raise TimeoutError(f"No response within {timeout}s")


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

async def handshake(transport: BleTransport, crypto: NbCrypto,
                    bt_name: str, mac: str,
                    gen: ProtocolGen = ProtocolGen.GEN2,
                    stored_password: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """
    Complete the 3-phase Encryption2 handshake.

    Returns (password, auth, sn).
    """
    # Gen2 uses FW_DATA as initial key2; Gen3 uses None
    # derive_key truncates to [:16] internally
    initial_key2 = FW_DATA if gen == ProtocolGen.GEN2 else None

    # ── Phase 1: PRE_COMM ──────────────────────────────────────────
    log.info("Phase 1: PRE_COMM (%s)", gen.value)
    crypto.reset_sn()
    crypto.set_key(bt_name.encode(), initial_key2)

    frame = build_pre_comm(gen=gen)
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)

    resp_enc = await transport.recv(timeout=5.0)
    resp_plain, rc = crypto.decrypt(resp_enc)
    log.info("PRE_COMM response (rc=%d): %s", rc, frame_hex(resp_plain))

    # Segway/Ninebot devices echo the request back 1:1 when they reject it.
    # That happens for two reasons, both of which we can't recover from here:
    #   1) Wrong key — the device name we keyed with is not this scooter's serial.
    #   2) The scooter uses V3Auth (Encryption3, newest models e.g. E300SE),
    #      which this client does not implement.
    if resp_plain == frame:
        raise RuntimeError(
            "Device echoed the PRE_COMM frame unchanged "
            f"({frame_hex(resp_plain)}) — it rejected the handshake.\n"
            f"  • Check the name: it must be this scooter's exact serial / "
            f"advertised BLE name (it is the encryption key). We used "
            f"'{bt_name}'. Run the 'scan' command and use that name.\n"
            "  • If the name is correct, the scooter likely uses V3Auth "
            "(newest models such as the E300SE), which is not supported.")

    resp = parse_frame(resp_plain)
    if resp is None or resp.cmd != CMD_PRE_COMM:
        raise RuntimeError(f"Invalid PRE_COMM response: {frame_hex(resp_plain)}")

    if len(resp.data) < 30:
        raise RuntimeError(f"PRE_COMM data too short: {len(resp.data)} bytes")

    auth = resp.data[0:16]
    sn = resp.data[16:30]
    has_stored_pwd = resp.index != 0

    log.info("  auth: %s", auth.hex())
    log.info("  sn:   %s (%s)", sn.hex(), sn.decode("ascii", errors="replace"))
    log.info("  has_stored_pwd: %s", has_stored_pwd)

    # Set auth param and enable SN mode
    crypto.set_auth_param(auth)
    crypto.start_sn()

    # Check for stored password
    password = None
    if stored_password:
        password = stored_password
        log.info("  Using CLI-provided password (%d bytes)", len(password))
        log.debug("  password=%s", password.hex())

    # ── Phase 2: SET_PWD (if needed) ───────────────────────────────
    if password is None and has_stored_pwd:
        log.warning("  Device has stored password but none provided!")
        log.warning("  Use --password <hex> with the password from iPhone backup")
        log.warning("  Attempting SET_PWD anyway (will likely fail)...")

    if password is None:
        log.info("Phase 2: SET_PWD")
        crypto.set_key(bt_name.encode(), auth)

        password = generate_password(auth)
        log.info("  Generated new password (%d bytes)", len(password))
        log.debug("  password=%s", password.hex())

        frame = build_set_pwd(password, gen=gen)
        encrypted = crypto.encrypt(frame)
        await transport.send(encrypted)

        resp_enc = await transport.recv(timeout=10.0)
        resp_plain, rc = crypto.decrypt(resp_enc)
        log.info("SET_PWD response (rc=%d): %s", rc, frame_hex(resp_plain))

        resp = parse_frame(resp_plain)
        if resp is None or resp.cmd != CMD_SET_PWD:
            raise RuntimeError(f"Invalid SET_PWD response: {frame_hex(resp_plain)}")

        if resp.index == 0:
            log.warning("  Device waiting for button press...")
            # Wait longer for user interaction
            resp_enc = await transport.recv(timeout=60.0)
            resp_plain, rc = crypto.decrypt(resp_enc)
            resp = parse_frame(resp_plain)
            if resp is None or resp.index != 1:
                raise RuntimeError("SET_PWD failed (button not pressed?)")

        if resp.index != 1:
            raise RuntimeError(f"SET_PWD rejected: index={resp.index}")

        log.info("  Password accepted!")

    # ── Phase 3: AUTH ──────────────────────────────────────────────
    log.info("Phase 3: AUTH")
    crypto.set_key(password, auth)

    frame = build_auth(sn, gen=gen)
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)

    resp_enc = await transport.recv(timeout=5.0)
    resp_plain, rc = crypto.decrypt(resp_enc)
    log.info("AUTH response (rc=%d): %s", rc, frame_hex(resp_plain))

    resp = parse_frame(resp_plain)
    if resp is None or resp.cmd != CMD_AUTH:
        raise RuntimeError(f"Invalid AUTH response: {frame_hex(resp_plain)}")

    if resp.index != 1:
        log.warning("AUTH failed (index=%d), clearing stored password", resp.index)
        raise RuntimeError(f"AUTH rejected: index={resp.index}")

    log.info("  Authenticated!")

    return password, auth, sn


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

async def cmd_read_speed(transport: BleTransport, crypto: NbCrypto,
                         gen: ProtocolGen = ProtocolGen.GEN2) -> int:
    """Read the current speed limit."""
    frame = build_read_speed(gen=gen)
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)

    resp_enc = await transport.recv(timeout=5.0)
    resp_plain, rc = crypto.decrypt(resp_enc)
    log.info("Read speed response (rc=%d): %s", rc, frame_hex(resp_plain))

    resp = parse_frame(resp_plain)
    if resp is None:
        raise RuntimeError(f"Invalid response: {frame_hex(resp_plain)}")

    if resp.cmd == CMD_READ_RESP and len(resp.data) >= 2:
        speed = struct.unpack("<H", resp.data[:2])[0]
        return speed
    else:
        raise RuntimeError(f"Unexpected response: cmd=0x{resp.cmd:02X}, data={resp.data.hex()}")


async def cmd_set_speed(transport: BleTransport, crypto: NbCrypto, speed: int,
                        gen: ProtocolGen = ProtocolGen.GEN2):
    """Write a new speed limit (WRITE_NR — no response expected)."""
    frame = build_write_speed(speed, gen=gen)
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)
    log.info("Speed limit set command sent: %d km/h", speed)
    # WRITE_NR doesn't get a response, but wait briefly for any error
    try:
        resp_enc = await transport.recv(timeout=2.0)
        resp_plain, rc = crypto.decrypt(resp_enc)
        resp = parse_frame(resp_plain)
        if resp:
            log.info("Got response: cmd=0x%02X index=0x%02X data=%s",
                     resp.cmd, resp.index, resp.data.hex())
    except TimeoutError:
        pass  # Expected for WRITE_NR


async def send_and_recv(transport: BleTransport, crypto: NbCrypto,
                        frame: bytes, timeout: float = 5.0) -> NbFrame | None:
    """Encrypt, send a frame and return the parsed decrypted response."""
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)
    resp_enc = await transport.recv(timeout=timeout)
    resp_plain, rc = crypto.decrypt(resp_enc)
    if rc != 0:
        log.warning("Decrypt rc=%d: %s", rc, frame_hex(resp_plain))
    return parse_frame(resp_plain)


async def read_register_u16(transport: BleTransport, crypto: NbCrypto,
                            frame: bytes) -> int | None:
    """Send a READ, return the 2-byte LE response as int."""
    resp = await send_and_recv(transport, crypto, frame)
    if resp and resp.cmd == CMD_READ_RESP and len(resp.data) >= 2:
        return struct.unpack("<H", resp.data[:2])[0]
    return None


async def read_register_u32(transport: BleTransport, crypto: NbCrypto,
                            frame: bytes) -> int | None:
    """Send a READ, return the 4-byte LE response as int."""
    resp = await send_and_recv(transport, crypto, frame)
    if resp and resp.cmd == CMD_READ_RESP and len(resp.data) >= 4:
        return struct.unpack("<I", resp.data[:4])[0]
    return None


async def read_register_bytes(transport: BleTransport, crypto: NbCrypto,
                              frame: bytes) -> bytes | None:
    """Send a READ, return the raw response data."""
    resp = await send_and_recv(transport, crypto, frame)
    if resp and resp.cmd == CMD_READ_RESP:
        return resp.data
    return None


def fmt_version(v: int | None) -> str:
    """Format a 2-byte version as major.minor.patch."""
    if v is None:
        return "?"
    return f"{(v >> 8) & 0xFF}.{(v >> 4) & 0xF}.{v & 0xF}"


async def cmd_info(transport: BleTransport, crypto: NbCrypto,
                   gen: ProtocolGen = ProtocolGen.GEN2):
    """
    Read dashboard info — matches the exact capture sequence.

    Startup reads (frames 4-17):
      VCU:0x03 rMainPower, BLE:0x50 rFunSupBool, DIS:0x7D rFunBool,
      DIS:0x10 rSN, DIS:0xB2 rBool, VCU:0x28 rECUPN

    Polling loop (frames 18+, ~1s):
      DIS:0xB2 rBool, DIS:0x1C rAlarm, VCU:0x03 rMainPower,
      DIS:0x39 rTimeFull, DIS:0x25 rLeftMileage, DIS:0xB5 rBattery,
      DIS:0xAF rPreciseMileage

    Settings page (frames 168+):
      DIS:0x7D rFunBool, DIS:0x8A rFunAppBool, DIS:0x7C rCTLBool2,
      DIS:0x93 rLimitSpeed, DIS:0x8C rFunAppBool2, DIS:0x75 rWarn
    """
    g = gen

    async def safe_u16(frame, label=""):
        try:
            return await read_register_u16(transport, crypto, frame)
        except (TimeoutError, RuntimeError) as e:
            log.debug("  %s: %s", label or "read", e)
            return None

    async def safe_u32(frame, label=""):
        try:
            return await read_register_u32(transport, crypto, frame)
        except (TimeoutError, RuntimeError) as e:
            log.debug("  %s: %s", label or "read", e)
            return None

    async def safe_bytes(frame, label=""):
        try:
            return await read_register_bytes(transport, crypto, frame)
        except (TimeoutError, RuntimeError) as e:
            log.debug("  %s: %s", label or "read", e)
            return None

    # ── Startup reads (capture frames 4-17) ──
    main_pwr = await safe_u16(build_read_main_power(gen=g), "mainPwr")
#    fun_sup = await safe_bytes(build_read_fun_sup_bool(gen=g), "funSup")
#    fun_bool = await safe_u16(build_read_fun_bool(gen=g), "funBool")
    sn_data = await safe_bytes(build_read_sn(gen=g), "sn")
    sn_str = sn_data.decode("ascii", errors="replace").rstrip("\x00") if sn_data else "?"
    rbool = await safe_u16(build_read_bool(gen=g), "rBool")
    ecu_pn = await safe_bytes(build_read_ecu_pn(gen=g), "ecuPN")
    ecu_pn_str = ecu_pn.decode("ascii", errors="replace").rstrip("\x00") if ecu_pn else "?"

    # ── Polling loop reads (capture frames 18+) ──
    alarm = await safe_u16(build_read_alarm(gen=g), "alarm")
    time_full = await safe_u16(build_read_time_full(gen=g), "timeFull")
    left_mi = await safe_u16(build_read_left_mileage(gen=g), "leftMi")
    battery = await safe_u16(build_read_battery(gen=g), "battery")
    prec_mi = await safe_u16(build_read_precise_mileage(gen=g), "precMi")

    # ── Settings page reads (capture frames 168+) ──
#    fun_app = await safe_u16(build_read_fun_app_bool(gen=g), "funApp")
#    ctl_bool2 = await safe_u16(build_read_ctl_bool2(gen=g), "ctlBool2")
    spd_lim = await safe_u16(build_read_speed(gen=g), "spdLim")
#    fun_app2 = await safe_u16(build_read_fun_app_bool(gen=g), "funApp2")
    warn = await safe_u16(build_read_warn(gen=g), "warn")

    # ── Extra reads (not in capture but useful) ──
    speed = await safe_u16(build_read_speed_live(gen=g), "speed")
    max_spd = await safe_u16(build_read_rated_speed(gen=g), "maxSpd")
    mileage = await safe_u32(build_read_mileage(gen=g), "mileage")  # u32, 1m unit
    # rRunningTime and rSingleMileage are u16 per device_commands.json — reading
    # as u32 bleeds the next register's bytes into the value.
    runtime = await safe_u16(build_read_running_time(gen=g), "runtime")
    single_mi = await safe_u16(build_read_single_mileage(gen=g), "singleMi")
    ave_spd = await safe_u16(build_read_ave_speed(gen=g), "aveSpd")
    sig_max = await safe_u16(build_read_sig_max_speed(gen=g), "sigMax")
    power_raw = await safe_u16(build_read_power(gen=g), "power")
    # rPower is int16 — regen braking returns negative wattage.
    power = (power_raw - 0x10000) if power_raw and power_raw > 0x7FFF else power_raw
    alarm_vol = await safe_u16(build_read_alarm_volume(gen=g), "alarmVol")
    alarm_lvl = await safe_u16(build_read_alarm_level(gen=g), "alarmLvl")
    auto_lock = await safe_u16(build_read_auto_lock(gen=g), "autoLock")
    active_mode = await safe_u16(build_read_bool2(gen=g), "rBool2")

    # ── Versions ──
#    dis_ver = await safe_u16(build_read_dis_version(gen=g), "disVer")
#    mcu_ver = await safe_u16(build_read_mcu_version(gen=g), "mcuVer")
#    ble_ver = await safe_u16(build_read_ble_version(gen=g), "bleVer")
#    ecu_ver = await safe_u16(build_read_ecu_version(gen=g), "ecuVer")
#    bms_ver = await safe_u16(build_read_bms1_version(gen=g), "bmsVer")

    # ── BMS (may be asleep when vehicle is off) ──
    voltage = await safe_u16(build_read_voltage(gen=g), "voltage")
    cycles = await safe_u16(build_read_cycle_count(gen=g), "cycles")

    def v(x, unit="", scale=1):
        return f"{x * scale}{unit}" if x is not None else "?"

    def h(x):
        return f"0x{x:04X}" if x is not None else "?"

    def scale(value,scale):
        return value * scale if value is not None else -1


    # Decode rWarn split: low=volume, high=preset.
    warn_vol_str = f"{warn_volume(warn)}" if warn is not None else "?"
    warn_pre_str = f"Sound {warn_preset(warn) + 1}" if warn is not None else "?"
    # Decode alarm sensitivity enum.
    alarm_names = {1: "Sensitive", 2: "High", 3: "Standard", 4: "Low"}
    alarm_lvl_str = alarm_names.get(alarm_lvl, f"?({alarm_lvl})") if alarm_lvl else "?"
    # Decode active riding mode from rBool2 bitmask.
    mode_names = {0x01: "ECO", 0x02: "Coast", 0x04: "Furious", 0x08: "M1", 0x10: "M2"}
    mode_str = "?"
    if active_mode is not None:
        for mask, name in mode_names.items():
            if active_mode & mask:
                mode_str = f"{name} (0x{active_mode:04X})"
                break
        else:
            mode_str = f"none (0x{active_mode:04X})"

    return {"sn":sn_str,
            "ecu":ecu_pn_str,
            "main_power":main_pwr,
            "mode":mode_str,
            "batterie":battery,
            "speed": scale(speed,0.1),
            "ave_spd": scale(ave_spd,0.1),
            "sig_max": scale(sig_max,0.1),
            "range_left" : scale(left_mi,0.1),
            "speed_limit" : (spd_lim),
            "speed_max" : scale(max_spd,0.1),
            "speed_ave" : (ave_spd),
            "speed_limit" : scale(ave_spd,0.1),
            "mileage" : scale(mileage,0.001),
            "trip_mileage" : (single_mi),
            "time_full" : (time_full),
            "power" : (power),
            "alarm" : (alarm),
            "alarm_vol" : (alarm_vol),
            "alarm_sens" : (alarm_lvl_str),
            "auto_lock" : (auto_lock),
            "promt_vol" : (warn_vol_str),
            "promt_sound" : (warn_pre_str),
            "voltage" : scale(voltage,0.01),
            "bms_cycles" : (cycles),
            }

    #print(f"Serial Number:  {sn_str}")
    #print(f"ECU PN:         {ecu_pn_str}")
    #print(f"Main power:     {v(main_pwr)} (503=off, 511=on)")
    #print(f"Active mode:    {mode_str}")
    #print(f"Battery:        {v(battery, '%')}")
    #print(f"Speed:          {v(speed, ' km/h', 0.1)}")
    #print(f"Ave speed:      {v(ave_spd, ' km/h', 0.1)}")
    #print(f"Trip max spd:   {v(sig_max, ' km/h', 0.1)}")
    #print(f"Range left:     {v(left_mi, ' km', 0.1)}")
    #print(f"Speed limit:    {v(spd_lim, ' km/h')}")
    #print(f"Max/rated:      {v(max_spd, ' km/h', 0.1)}")
    #print(f"Odometer:       {v(mileage, ' km', 0.001) if mileage else '?'}")
    #print(f"Trip distance:  {v(single_mi, ' km', 0.01)}")
    #print(f"Precise mi:     {v(prec_mi)}")
    #print(f"Trip time:      {v(runtime, 's')}")
    #print(f"Time to full:   {v(time_full)} (65535=N/A)")
    #print(f"Power:          {v(power, ' W')} (negative=regen)")
    #print(f"Alarm:          {h(alarm)}")
    #print(f"Alarm volume:   {v(alarm_vol, '%')}")
    #print(f"Alarm sens:     {alarm_lvl_str}")
    #print(f"Auto-lock:      {v(auto_lock, 's')}")
    #print(f"Prompt volume:  {warn_vol_str}%")
    #print(f"Sound preset:   {warn_pre_str}")
    #print(f"Voltage:        {v(voltage, ' V', 0.01)}")
    #print(f"BMS cycles:     {v(cycles)}")
    #print(f"rBool:          {h(rbool)} (2882=off, 2881=on)")
    #print(f"FunBool:        {h(fun_bool)}")
    #print(f"FunAppBool:     {h(fun_app)} (bit 4=electric brake available)")
    #print(f"FunAppBool2:    {h(fun_app2)} (bit 1=TCS available)")
    #print(f"CTLBool2:       {h(ctl_bool2)} (bit 10=ele brake rev, bit 13=TCS rev)")
    #print(f"FunSupBool:     {fun_sup.hex() if fun_sup else '?'}")
    #print(f"Versions:       DIS={fmt_version(dis_ver)}  MCU={fmt_version(mcu_ver)}  "
    #      f"BLE={fmt_version(ble_ver)}  ECU={fmt_version(ecu_ver)}  BMS={fmt_version(bms_ver)}")


async def cmd_set_sound(transport: BleTransport, crypto: NbCrypto,
                        value: int, gen: ProtocolGen = ProtocolGen.GEN2):
    """Set rWarn (DIS:0x75) as a raw u16 value. Low byte=volume, high byte=preset."""
    frame = build_set_warn(value, gen=gen)
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)
    log.info("Set rWarn: %d (0x%04X) — volume=%d preset=%d",
             value, value, warn_volume(value), warn_preset(value))
    try:
        resp_enc = await transport.recv(timeout=2.0)
        resp_plain, rc = crypto.decrypt(resp_enc)
        resp = parse_frame(resp_plain)
        if resp:
            log.info("Got response: cmd=0x%02X index=0x%02X data=%s",
                     resp.cmd, resp.index, resp.data.hex())
    except TimeoutError:
        pass


# ---------------------------------------------------------------------------
# New one-shot actions + settings — matching Flutter app findings
# ---------------------------------------------------------------------------

async def cmd_honk(transport: BleTransport, crypto: NbCrypto,
                   gen: ProtocolGen = ProtocolGen.GEN2):
    """Play alarm sound + flash lights (spec: playSound, DIS cmd 0x11)."""
    frame = build_play_sound(gen=gen)
    await transport.send(crypto.encrypt(frame))
    log.info("Honk + flash sent")


async def cmd_flash(transport: BleTransport, crypto: NbCrypto,
                    gen: ProtocolGen = ProtocolGen.GEN2):
    """Flash lights only (spec: playLight, HEP cmd 0x11 index 1)."""
    frame = build_play_light(gen=gen)
    await transport.send(crypto.encrypt(frame))
    log.info("Flash lights sent")


async def cmd_set_warn_split(transport: BleTransport, crypto: NbCrypto,
                             volume: int, preset: int,
                             gen: ProtocolGen = ProtocolGen.GEN2):
    """Set rWarn via volume (0-100) + preset (0-2) fields."""
    if not (0 <= volume <= 100):
        raise ValueError(f"volume must be 0-100, got {volume}")
    if not (0 <= preset <= 2):
        raise ValueError(f"preset must be 0-2, got {preset}")
    value = pack_warn(volume=volume, preset=preset)
    frame = build_set_warn(value, gen=gen)
    await transport.send(crypto.encrypt(frame))
    log.info("Set rWarn: volume=%d preset=Sound%d (raw=0x%04X)",
             volume, preset + 1, value)


async def cmd_set_alarm_level(transport: BleTransport, crypto: NbCrypto,
                              level: int, gen: ProtocolGen = ProtocolGen.GEN2):
    """Set alarm sensitivity (DIS 0x77). 1=Sensitive, 2=High, 3=Standard, 4=Low."""
    if level not in (1, 2, 3, 4):
        raise ValueError(f"alarm level must be 1-4, got {level}")
    frame = build_set_alarm_level(level, gen=gen)
    await transport.send(crypto.encrypt(frame))
    names = {1: "Sensitive", 2: "High", 3: "Standard", 4: "Low"}
    log.info("Set alarm sensitivity: %s (level=%d)", names[level], level)


async def cmd_set_alarm_volume(transport: BleTransport, crypto: NbCrypto,
                               volume: int, gen: ProtocolGen = ProtocolGen.GEN2):
    """Set alarm volume (DIS 0x76, 0-100)."""
    if not (0 <= volume <= 100):
        raise ValueError(f"volume must be 0-100, got {volume}")
    frame = build_set_alarm_volume(volume, gen=gen)
    await transport.send(crypto.encrypt(frame))
    log.info("Set alarm volume: %d", volume)


async def cmd_set_auto_lock(transport: BleTransport, crypto: NbCrypto,
                            seconds: int, gen: ProtocolGen = ProtocolGen.GEN2):
    """Set auto-lock timer seconds (DIS 0x85)."""
    frame = build_set_auto_lock(seconds, gen=gen)
    await transport.send(crypto.encrypt(frame))
    log.info("Set auto-lock: %ds", seconds)


# DIS 0xAA rBool2 riding-mode bitmask — bit positions per device_ui_gear.json.
_MODE_BITS = {
    "eco": 0,
    "coast": 1,
    "furious": 2,
    "m1": 3,
    "m2": 4,
}


async def cmd_set_mode(transport: BleTransport, crypto: NbCrypto,
                       mode: str, gen: ProtocolGen = ProtocolGen.GEN2):
    """Switch active riding mode by name (eco/coast/furious/m1/m2)."""
    key = mode.lower()
    if key not in _MODE_BITS:
        raise ValueError(f"mode must be one of {list(_MODE_BITS)}, got {mode}")
    mask = 1 << _MODE_BITS[key]
    frame = build_set_bool2(mask, gen=gen)
    await transport.send(crypto.encrypt(frame))
    log.info("Set riding mode: %s (rBool2=0x%04X)", key, mask)


async def cmd_read_reg(transport: BleTransport, crypto: NbCrypto,
                       target: int, register: int, length: int,
                       gen: ProtocolGen = ProtocolGen.GEN2):
    """Read an arbitrary register (generic)."""
    frame = build_read(target, register, length, gen=gen)
    resp = await send_and_recv(transport, crypto, frame)
    if resp and resp.cmd == CMD_READ_RESP:
        print(f"[0x{target:02X}:0x{register:02X}] ({length}B) = {resp.data.hex()}", end="")
        if len(resp.data) == 2:
            val = struct.unpack("<H", resp.data[:2])[0]
            print(f"  ({val})", end="")
        elif len(resp.data) == 4:
            val = struct.unpack("<I", resp.data[:4])[0]
            print(f"  ({val})", end="")
        print()
    else:
        print(f"[0x{target:02X}:0x{register:02X}] No READ_RSP (got: {resp})")


async def cmd_write_reg(transport: BleTransport, crypto: NbCrypto,
                        target: int, register: int, data_hex: str,
                        gen: ProtocolGen = ProtocolGen.GEN2):
    """Write an arbitrary register (generic WRITE_NR)."""
    data = bytes.fromhex(data_hex)
    frame = build_write_nr(target, register, data, gen=gen)
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)
    print(f"WRITE_NR [0x{target:02X}:0x{register:02X}] data={data_hex}")
    try:
        resp_enc = await transport.recv(timeout=2.0)
        resp_plain, rc = crypto.decrypt(resp_enc)
        resp = parse_frame(resp_plain)
        if resp:
            print(f"  Response: cmd=0x{resp.cmd:02X} index=0x{resp.index:02X} data={resp.data.hex()}")
    except TimeoutError:
        pass


async def cmd_gear_info(transport: BleTransport, crypto: NbCrypto,
                        gen: ProtocolGen = ProtocolGen.GEN2):
    """Read all gear/speed-related registers."""
    g = gen
    mcu_max = await read_register_u16(transport, crypto, build_read_mcu_max_speed(gen=g))
    top_spd = await read_register_u16(transport, crypto, build_read_gear_top_speed(gen=g))
    acc_spd = await read_register_u16(transport, crypto, build_read_gear_acc_speed(gen=g))
    safe_lock = await read_register_u16(transport, crypto, build_read_speed_safe_lock(gen=g))
    spd_lim = await read_register_u16(transport, crypto, build_read_speed(gen=g))
    rated = await read_register_u16(transport, crypto, build_read_rated_speed(gen=g))
    cfg_mode = await read_register_u16(transport, crypto, build_read_cfg_mode(gen=g))

    # Read full gear profile
    gear_data = await read_register_bytes(transport, crypto, build_read_gear_data(1, gen=g))

    def v(x, unit=""):
        return f"{x}{unit}" if x is not None else "?"

    print(f"MCU max speed:     {v(mcu_max, ' km/h')} (firmware absolute cap)")
    print(f"Gear top speed:    {v(top_spd, ' km/h')} (active mode, MCU:0x31)")
    print(f"Acc speed limit:   {v(acc_spd)} (MCU:0x2D, 0-100)")
    print(f"Speed safe lock:   {v(safe_lock)} (MCU:0x53, MOLE-gated)")
    print(f"DIS speed limit:   {v(spd_lim, ' km/h')} (DIS:0x93)")
    print(f"Rated/max speed:   {v(rated, ' km/h')} (DIS:0x48, read-only)")
    print(f"Config mode:       {v(cfg_mode)} (DIS:0x74)")

    if gear_data and len(gear_data) >= 32:
        # Parse gear profile offsets from device_gear_default.json
        energy = struct.unpack_from("<H", gear_data, 20)[0]
        acc_s = struct.unpack_from("<H", gear_data, 22)[0]
        acc_sens = struct.unpack_from("<H", gear_data, 24)[0]
        tcs = struct.unpack_from("<H", gear_data, 26)[0]
        nitro = struct.unpack_from("<H", gear_data, 28)[0]
        top = struct.unpack_from("<H", gear_data, 30)[0]
        sens_names = {0: "low", 1: "moderate", 2: "high"}
        tcs_names = {0: "off", 1: "moderate", 2: "strongest"}
        print(f"\nGear profile 1 (32B): {gear_data.hex()}")
        print(f"  Energy recovery: {energy} (20/40/60/80/100)")
        print(f"  Acc speed limit: {acc_s} (0-100)")
        print(f"  Acc sensitivity: {acc_sens} ({sens_names.get(acc_sens, '?')})")
        print(f"  TCS:             {tcs} ({tcs_names.get(tcs, '?')})")
        print(f"  Nitro:           {nitro} ({'on' if nitro else 'off'})")
        print(f"  Top speed:       {top} km/h")
    elif gear_data:
        print(f"\nGear profile 1 ({len(gear_data)}B): {gear_data.hex()}")


async def cmd_set_gear(transport: BleTransport, crypto: NbCrypto,
                       param: str, value: int,
                       gen: ProtocolGen = ProtocolGen.GEN2):
    """Set a gear parameter."""
    builders = {
        "top-speed": (build_set_gear_top_speed, "Gear top speed"),
        "acc-speed": (build_set_gear_acc_speed, "Acc speed limit"),
        "acc-sens": (build_set_gear_acc_sens, "Acc sensitivity"),
        "tcs": (build_set_gear_tcs, "TCS"),
        "nitro": (build_set_gear_nitro, "Nitro"),
        "energy": (build_set_gear_energy, "Energy recovery"),
        "safe-lock": (build_set_speed_safe_lock, "Speed safe lock"),
    }
    builder_fn, label = builders[param]
    if param == "nitro":
        frame = builder_fn(bool(value), gen=gen)
    else:
        frame = builder_fn(value, gen=gen)
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)
    log.info("%s set to %d", label, value)
    try:
        resp_enc = await transport.recv(timeout=2.0)
        resp_plain, rc = crypto.decrypt(resp_enc)
        resp = parse_frame(resp_plain)
        if resp:
            log.info("Got response: cmd=0x%02X index=0x%02X data=%s",
                     resp.cmd, resp.index, resp.data.hex())
    except TimeoutError:
        pass


async def cmd_vehicle_action(transport: BleTransport, crypto: NbCrypto,
                             action: str, ident: bytes,
                             gen: ProtocolGen = ProtocolGen.GEN2):
    """Send a vehicle action command (power-on, power-off, open-seat)."""
    builders = {
        "power-on": build_open_acc,
        "power-off": build_close_acc,
        "open-seat": build_open_trunk,
    }
    builder = builders[action]
    frame = builder(ident, gen=gen)
    encrypted = crypto.encrypt(frame)
    await transport.send(encrypted)
    log.info("Vehicle action '%s' sent", action)
    # Wait briefly for any response
    try:
        resp_enc = await transport.recv(timeout=2.0)
        resp_plain, rc = crypto.decrypt(resp_enc)
        resp = parse_frame(resp_plain)
        if resp:
            log.info("Got response: cmd=0x%02X index=0x%02X data=%s",
                     resp.cmd, resp.index, resp.data.hex())
    except TimeoutError:
        pass  # Expected for WRITE_NR


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def detect_auth_version(manufacturer_data: dict[int, bytes] | None) -> int | None:
    """
    Best-effort: extract the encrypt-protocol version from Ninebot/Segway
    manufacturer-specific advertisement data. Returns 2 (V2, supported),
    3 (V3Auth, NOT supported), or None if it can't be determined.

    Layout per the official app (ScanRecord): the version byte sits at payload
    offset 1 for the primary manufacturer id and offset 2 for the secondary one.
    Advisory only — never used to block a connection.
    """
    for cid, payload in (manufacturer_data or {}).items():
        if cid in (20034, 16974) and len(payload) >= 2 and payload[1] in (2, 3):
            return payload[1]
        if cid in (20035, 16975) and len(payload) >= 3 and payload[2] in (2, 3):
            return payload[2]
    return None


def _auth_tag(ver: int | None) -> str:
    return {2: "authV2 (supported)",
            3: "authV3 (NOT supported)"}.get(ver, "auth=? (unknown)")


async def read_device_name(client: BleakClient) -> str | None:
    """Read the GATT Device Name (0x2A00) — the serial used as the V2 key."""
    try:
        val = await client.read_gatt_char(GATT_DEVICE_NAME)
        name = val.decode("ascii", errors="ignore").replace("\x00", "").strip()
        return name or None
    except Exception as e:  # noqa: BLE001 - advisory read, never fatal here
        log.debug("Could not read GATT device name: %s", e)
        return None


async def do_scan(name_filter: str | None = None):
    """Scan for Segway/Ninebot BLE devices and report their auth version."""
    print("Scanning for BLE devices (10 seconds)...")
    discovered = await BleakScanner.discover(timeout=10.0, return_adv=True)

    found = []
    for d, adv in discovered.values():
        name = d.name or (adv.local_name if adv else "") or ""
        mfr = (adv.manufacturer_data if adv else None) or {}
        is_ninebot = (any(x in name.upper() for x in ["S1D", "NINEBOT", "SEGWAY", "NB-"])
                      or any(cid in NINEBOT_MFR_IDS for cid in mfr))
        if name_filter and name_filter.lower() not in name.lower():
            continue
        if is_ninebot:
            # Keep the advertised name alongside the device — it is the serial
            # (V2 key) and may come from adv.local_name when d.name is None.
            found.append((d, name))
            rssi = adv.rssi if adv else "?"
            print(f"  [{rssi:>4} dBm] {d.address}  {name or '(unknown)'}  "
                  f"[{_auth_tag(detect_auth_version(mfr))}]")

    if not found:
        print("\nNo matching devices found. Showing all nearby devices:")
        ranked = sorted(discovered.values(),
                        key=lambda da: da[1].rssi if da[1] else -999, reverse=True)
        for d, adv in ranked[:20]:
            name = d.name or (adv.local_name if adv else "") or "(unknown)"
            rssi = adv.rssi if adv else "?"
            print(f"  [{rssi:>4} dBm] {d.address}  {name}")

    return found


# ---------------------------------------------------------------------------
# Connect & discover services
# ---------------------------------------------------------------------------

async def find_characteristics(client: BleakClient,
                               gen: ProtocolGen = ProtocolGen.GEN2) -> tuple[str, str]:
    """
    Discover write and notify characteristic UUIDs.
    Gen2 prefers Nordic UART, Gen3 prefers Ninebot Custom.
    """
    services = client.services

    # Log all services for debugging
    for svc in services:
        log.debug("Service: %s", svc.uuid)
        for char in svc.characteristics:
            props = ",".join(char.properties)
            log.debug("  Char: %s [%s]", char.uuid, props)

    has_nb = any(svc.uuid.lower() == NB_SERVICE for svc in services)
    has_nordic = any(svc.uuid.lower() == NORDIC_SERVICE for svc in services)

    # Gen2 prefers Nordic UART; Gen3 prefers Ninebot Custom
    if gen == ProtocolGen.GEN2:
        order = [(has_nordic, "Nordic UART", NORDIC_WRITE, NORDIC_NOTIFY),
                 (has_nb, "Ninebot Custom", NB_WRITE, NB_NOTIFY)]
    else:
        order = [(has_nb, "Ninebot Custom", NB_WRITE, NB_NOTIFY),
                 (has_nordic, "Nordic UART", NORDIC_WRITE, NORDIC_NOTIFY)]

    for found, name, write_uuid, notify_uuid in order:
        if found:
            log.info("Found %s service", name)
            return write_uuid, notify_uuid

    # Fallback: scan for any service with 6e4000xx UUIDs
    for svc in services:
        if "6e4000" in svc.uuid.lower():
            write_char = None
            notify_char = None
            for char in svc.characteristics:
                if "write" in char.properties:
                    write_char = char.uuid
                if "notify" in char.properties:
                    notify_char = char.uuid
            if write_char and notify_char:
                log.info("Found service %s (write=%s, notify=%s)",
                         svc.uuid, write_char, notify_char)
                return write_char, notify_char

    raise RuntimeError("No compatible BLE service found. Available services: " +
                       ", ".join(svc.uuid for svc in services))


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

async def get_info(address,bt_name,gen,password):
    """Connect to device and execute the requested command."""
    # Gen2 uses FW_DATA[:16] as ECB input for non-SN mode
    ecb_input = FW_DATA[:16] if gen == ProtocolGen.GEN2 else b"\x00" * 16

    print(f"Connecting to {address} ({gen.value})...")
    async with BleakClient(address, timeout=15.0) as client:
        print(f"Connected! MTU: {client.mtu_size}")

        # The serial (GATT Device Name) IS the V2 encryption key. Read it from
        # the device so we always key with the right scooter's serial. A wrong
        # name produces a silently-rejected (echoed) handshake.
        if not bt_name:
            bt_name = await read_device_name(client)
            if bt_name:
                print(f"Device name (encryption key): {bt_name}")
        if not bt_name:
            print("Error: could not read the device name. Pass --name <serial> "
                  "(the scooter's exact advertised name; see 'scan').")
            return

        write_uuid, notify_uuid = await find_characteristics(client, gen=gen)
        transport = BleTransport(client, write_uuid, notify_uuid)
        await transport.start()

        crypto = NbCrypto(ecb_input=ecb_input)
        mac = address.upper()
        stored_pwd = bytes.fromhex(password) if password else None

        try:
            # Handshake
            password, auth, sn = await handshake(
                transport, crypto, bt_name, mac, gen=gen,
                stored_password=stored_pwd)
            sn_str = sn.decode("ascii", errors="replace")
            print(f"Authenticated! SN: {sn_str}")

            # Execute command
            data = await cmd_info(transport, crypto, gen=gen)
            print(data)
        finally:
            await transport.stop()
        return data

async def run(address,bt_name,gen,password,args):
        try:
            transport, crypto, gen = await connect(address,bt_name,gen,password)
            # Execute command
            if args.command == "read-speed":
                speed = await cmd_read_speed(transport, crypto, gen=gen)
                print(f"Current speed limit: {speed} km/h")

            elif args.command == "set-speed":
                target_speed = args.speed
                # Safety: read current speed first
                current = await cmd_read_speed(transport, crypto, gen=gen)
                print(f"Current speed limit: {current} km/h")
                print(f"Setting to: {target_speed} km/h")

                confirm = input("Proceed? [y/N] ").strip().lower()
                if confirm != "y":
                    print("Aborted.")
                    return

                await cmd_set_speed(transport, crypto, target_speed, gen=gen)
                print(f"Done! Speed limit set to {target_speed} km/h")

                # Verify
                await asyncio.sleep(0.5)
                verify = await cmd_read_speed(transport, crypto, gen=gen)
                print(f"Verified speed limit: {verify} km/h")

            elif args.command == "info":
                await cmd_info(transport, crypto, gen=gen)

            elif args.command == "gear-info":
                await cmd_gear_info(transport, crypto, gen=gen)

            elif args.command == "set-gear":
                await cmd_set_gear(transport, crypto,
                                   args.param, args.value, gen=gen)
                print(f"Gear param '{args.param}' set to {args.value}")

            elif args.command == "set-sound":
                await cmd_set_sound(transport, crypto, args.value, gen=gen)
                print(f"Sound preset set to {args.value}")

            elif args.command == "read-reg":
                await cmd_read_reg(transport, crypto,
                                   args.target, args.register, args.length, gen=gen)

            elif args.command == "write-reg":
                await cmd_write_reg(transport, crypto,
                                    args.target, args.register, args.data, gen=gen)

            elif args.command in ("power-on", "power-off", "open-seat"):
                ident = bytes.fromhex(args.ident)
                await cmd_vehicle_action(
                    transport, crypto, args.command, ident, gen=gen)
                print(f"Vehicle action '{args.command}' sent.")

            elif args.command == "honk":
                await cmd_honk(transport, crypto, gen=gen)
                print("Honk + flash sent.")

            elif args.command == "flash":
                await cmd_flash(transport, crypto, gen=gen)
                print("Flash lights sent.")

            elif args.command == "set-warn":
                await cmd_set_warn_split(transport, crypto,
                                         args.volume, args.preset, gen=gen)
                print(f"rWarn set: volume={args.volume}, preset=Sound{args.preset + 1}")

            elif args.command == "set-alarm-volume":
                await cmd_set_alarm_volume(transport, crypto, args.volume, gen=gen)
                print(f"Alarm volume set to {args.volume}.")

            elif args.command == "set-alarm-level":
                await cmd_set_alarm_level(transport, crypto, args.level, gen=gen)
                print(f"Alarm sensitivity level set to {args.level}.")

            elif args.command == "set-auto-lock":
                await cmd_set_auto_lock(transport, crypto, args.seconds, gen=gen)
                print(f"Auto-lock set to {args.seconds}s.")

            elif args.command == "set-mode":
                await cmd_set_mode(transport, crypto, args.mode, gen=gen)
                print(f"Riding mode: {args.mode}.")

            elif args.command == "handshake":
                print("Handshake complete.")

        finally:
            await transport.stop()

