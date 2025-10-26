Audio & Modulation Notes
========================

## CTCSS / DCS Tone Generation

- Tone index table: `DAT_8000ca00` contains 16-bit entries for the standard 42 CTCSS frequencies (value = Hz × 10). Functions such as `ToneMenu_ShowEntry (ToneMenu_ShowEntry (FUN_8000bd58))` and `ToneGraphic_Draw (ToneGraphic_Draw (FUN_8000cfd4))` pull from this table when displaying tone options.
- Wave output: `AudioDMA_Trigger (AudioDMA_Trigger (FUN_8000dca0))` writes DMA2 registers at 0x40020430, pointing to waveform buffers that drive DAC1 (`0x40007400`). Supporting helpers `DAC_ChannelGate (FUN_8000b368)` / `DAC_BufferGate (FUN_8000b388)` enable DAC channels and gates, while `DAC_WaveformWrite (FUN_8000b3a8)` updates waveform control words.
- User interface: `ToneMenu_SetLabel (FUN_8000bb08)`, `ToneMenu_ShowEntry (FUN_8000bd58)`, and `ToneGraphic_Draw (FUN_8000cfd4)` update the LCD tone menu, calling `FUN_8001403c` / `FUN_80014ad0` to show numeric values and bar graphs.
- Likely hardware pins: AT32 DAC1 outputs on PA4 (OUT1) and PA5 (OUT2). The firmware only references DAC base 0x40007400, so PA4 is the primary tone output. PA5 may be unused or reserved; confirm on the board (low confidence).

## APRS / AFSK Path

- Frame builder: functions around `FUN_8000997c` assemble APRS messages (strings `"APRS"`, `"APRS activation"` appear nearby). Whitening uses `Modem_Scramble_Data (Modem_Scramble_Data (FUN_8000b024))` before modulation.
- Tone generation: APRS routines reuse the same DAC pipeline. Waveform buffers `DAT_8000cfc0` / `DAT_8000cfc4` hold 1200/2200 Hz sinusoids; AFSK senders call `AudioDMA_Trigger` to stream them.
- Control flow: `APRS_Modem_CheckReady (FUN_8000f354)`, `APRS_Modem_ReadStatus (FUN_8000f380)`, `APRS_Modem_StartTX (FUN_8000f408)` manage APRS transmit cycles, toggling chip-select via `FUN_80026fb2` and mapping PTT states with `APRS_SetPTT (FUN_8000f2b0)`.

## Practical Notes

- To capture tone or APRS output, probe PA4 and watch DMA2 activity when `AudioDMA_Trigger` is invoked.
- Tone enable sequences set bits in the DAC control registers; look for `DAC_ChannelGate (FUN_8000b368)(0,1)` and `DAC_BufferGate (FUN_8000b388)(0,1)` calls.
- When reverse engineering modulation, log the buffers passed to `AudioDMA_Trigger`—they contain the time-domain waveform.
