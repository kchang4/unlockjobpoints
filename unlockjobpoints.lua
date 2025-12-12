--[[
* Addons - Copyright (c) 2025 Ashita Development Team
* Contact: https://www.ashitaxi.com/
* Contact: https://discord.gg/Ashita
*
* This file is part of Ashita.
*
* Ashita is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Ashita is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Ashita.  If not, see <https://www.gnu.org/licenses/>.
--]]

addon.name      = 'unlockjobpoints';
addon.author    = 'FFXI-Ashita';
addon.version   = '1.2.0';
addon.desc      = 'Unlocks the Job Points menu at any level (for 75-era servers)';
addon.link      = 'https://github.com/kchang4/unlockjobpoints';

-- Enable FFI for direct memory access
local ffi = require('ffi');
local jit = require('jit');
jit.on();

-- Configuration: Set to true to enable spoofing level to 99 for menu access
local SPOOF_LEVEL_99 = true;

--[[
* event: packet_in
* desc : Event called when the addon is processing incoming packets.
*
* Packet 0x0061 (CLISTATUS) layout:
*   0x00-0x03: Header (id, size, sync)
*   0x04-0x07: hpmax (int32)
*   0x08-0x0B: mpmax (int32)
*   0x0C: mjob_no (uint8) - main job id
*   0x0D: mjob_lv (uint8) - main job level  <-- THIS IS WHAT WE SPOOF
*   0x0E: sjob_no (uint8) - sub job id
*   0x0F: sjob_lv (uint8) - sub job level
*   ... more fields ...
*
* Packet 0x0063 type 0x05 (Job Points):
*   0x08: access flags (bit 0 = menu unlocked)
--]]
ashita.events.register('packet_in', 'packet_in_cb', function (e)
    local ptr = ffi.cast('uint8_t*', e.data_modified_raw);
    
    -- Packet 0x0061: CLISTATUS - Spoof main job level to 99
    if (e.id == 0x0061 and SPOOF_LEVEL_99) then
        local actualLevel = ptr[0x0D];
        if (actualLevel < 99) then
            ptr[0x0D] = 99;  -- Spoof level to 99 for client UI
            print(string.format('[JobPointsUnlock] Spoofed level %d -> 99 for menu access', actualLevel));
        end
    end
    
    -- Packet 0x0063: Miscdata - Force job points access flag
    if (e.id == 0x0063) then
        local packetType = ptr[0x04];
        
        -- Type 0x05 = Job Points
        if (packetType == 0x05) then
            local currentFlags = ptr[0x08];
            if (bit.band(currentFlags, 1) == 0) then
                ptr[0x08] = bit.bor(currentFlags, 1);
                print('[JobPointsUnlock] Enabled job points access flag');
            end
        end
    end
end);

--[[
* event: load
* desc : Event called when the addon is being loaded.
--]]
ashita.events.register('load', 'load_cb', function ()
    print('[JobPointsUnlock] Addon loaded - Job Points menu will be unlocked regardless of level');
    print('[JobPointsUnlock] Zone or relog to apply changes');
end);

--[[
* event: unload
* desc : Event called when the addon is being unloaded.
--]]
ashita.events.register('unload', 'unload_cb', function ()
    print('[JobPointsUnlock] Addon unloaded');
end);
