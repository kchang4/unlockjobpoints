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

--[[
    FALLBACK VERSION - Packet Spoofing Approach
    
    Use this version if the memory patching version (unlockjobpoints.lua) doesn't work.
    
    Rename this file to unlockjobpoints.lua and remove the original.
    
    IMPORTANT: This version will show your level as 99 in the client UI.
    This is because it spoofs the level in the incoming packet, which affects
    all systems that read the level (including the status display).
--]]

addon.name      = 'unlockjobpoints';
addon.author    = 'FFXI-Ashita';
addon.version   = '1.3.0-fallback';
addon.desc      = 'Unlocks the Job Points menu at any level via packet spoofing (SHOWS LVL 99)';
addon.link      = 'https://github.com/kchang4/unlockjobpoints';

local ffi = require('ffi');

-- Configuration
local config = {
    spoofLevel = 99,
    debug = false,
};

local realLevel = 0;

local function debugPrint(msg)
    if config.debug then
        print('[UnlockJobPoints] ' .. msg);
    end
end

--[[
* Packet spoofing approach
*
* Intercepts packet 0x0061 (CLISTATUS) and spoofs the player level to 99.
* This unlocks the Job Points menu but also changes the displayed level.
--]]
ashita.events.register('packet_in', 'packet_in_cb', function (e)
    local ptr = ffi.cast('uint8_t*', e.data_modified_raw);
    
    -- Packet 0x0061: CLISTATUS - Contains player level at offset 0x0D
    if (e.id == 0x0061) then
        realLevel = ptr[0x0D];
        if (realLevel < config.spoofLevel) then
            ptr[0x0D] = config.spoofLevel;
            debugPrint(string.format('Spoofed level %d -> %d', realLevel, config.spoofLevel));
        end
    end
    
    -- Packet 0x0063 type 0x05: Job Points access flag at offset 0x08
    if (e.id == 0x0063) then
        local packetType = ptr[0x04];
        if (packetType == 0x05) then
            local currentFlags = ptr[0x08];
            if (bit.band(currentFlags, 1) == 0) then
                ptr[0x08] = bit.bor(currentFlags, 1);
                debugPrint('Enabled job points access flag');
            end
        end
    end
end);

ashita.events.register('command', 'command_cb', function (e)
    local args = e.command:args();
    
    if (#args == 0 or (args[1]:lower() ~= '/ujp' and args[1]:lower() ~= '/unlockjobpoints')) then
        return;
    end
    
    e.blocked = true;
    
    if (#args == 1) then
        print('[UnlockJobPoints] Fallback (Packet Spoof) Version');
        print('  /ujp debug    - Toggle debug messages');
        print('  /ujp status   - Show current status');
        print('  /ujp level    - Show real vs spoofed level');
        return;
    end
    
    local cmd = args[2]:lower();
    
    if (cmd == 'debug') then
        config.debug = not config.debug;
        print(string.format('[UnlockJobPoints] Debug mode: %s', config.debug and 'ON' or 'OFF'));
    elseif (cmd == 'status') then
        print('[UnlockJobPoints] Fallback Mode (Packet Spoofing)');
        print(string.format('  Spoof level: %d', config.spoofLevel));
        print('  WARNING: Your level will display as 99!');
    elseif (cmd == 'level') then
        print(string.format('[UnlockJobPoints] Real level: %d, Displayed as: %d', realLevel, config.spoofLevel));
    end
end);

ashita.events.register('load', 'load_cb', function ()
    print('[UnlockJobPoints] v' .. addon.version .. ' loaded');
    print('[UnlockJobPoints] WARNING: This is the FALLBACK version using packet spoofing.');
    print('[UnlockJobPoints] Your level will display as 99 in the client!');
    print('[UnlockJobPoints] Use the main version (memory patch) if possible.');
end);

ashita.events.register('unload', 'unload_cb', function ()
    print('[UnlockJobPoints] Addon unloaded');
end);
