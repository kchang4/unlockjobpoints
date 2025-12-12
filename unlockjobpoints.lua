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
addon.version   = '1.1.0';
addon.desc      = 'Unlocks the Job Points menu at any level (for 75-era servers)';
addon.link      = 'https://github.com/kchang4/unlockjobpoints';

-- Enable FFI for direct memory access
local ffi = require('ffi');
local jit = require('jit');
jit.on();

--[[
* event: packet_in
* desc : Event called when the addon is processing incoming packets.
--]]
ashita.events.register('packet_in', 'packet_in_cb', function (e)
    -- Check for packet 0x63 (Miscdata)
    if (e.id == 0x0063) then
        local ptr = ffi.cast('uint8_t*', e.data_modified_raw);
        
        -- Get the packet type at offset 0x04 (uint16)
        local packetType = ptr[0x04];
        
        -- Type 0x05 = Job Points
        if (packetType == 0x05) then
            -- The access/flags byte is at offset 0x08
            -- We need to set bit 0 to 1 to enable the menu
            local currentFlags = ptr[0x08];
            
            if (bit.band(currentFlags, 1) == 0) then
                -- Force the access flag to 1
                ptr[0x08] = bit.bor(currentFlags, 1);
                print('[UnlockJobPoints] Enabled job points menu access');
            end
        end
    end
end);

--[[
* event: load
* desc : Event called when the addon is being loaded.
--]]
ashita.events.register('load', 'load_cb', function ()
    print('[UnlockJobPoints] Addon loaded - Job Points menu will be unlocked regardless of level');
    print('[UnlockJobPoints] Zone or relog to apply changes');
end);

--[[
* event: unload
* desc : Event called when the addon is being unloaded.
--]]
ashita.events.register('unload', 'unload_cb', function ()
    print('[UnlockJobPoints] Addon unloaded');
end);
