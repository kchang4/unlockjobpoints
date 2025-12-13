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

addon.name    = 'unlockjobpoints';
addon.author  = 'FFXI-Ashita';
addon.version = '2.0.0';
addon.desc    = 'Unlocks the Job Points menu at level 75 (for 75-era private servers).';
addon.link    = 'https://github.com/kchang4/unlockjobpoints';

require('common');
local chat = require('chat');

-- Patterns and their patch offsets
local patterns = {
    { name = 'MAIN MENU', pattern = '85C0740EF6000174??803D??????????73??8B4E086A086A05', offset = 15 },
    { name = 'JOB LIST',  pattern = '50E8????????83C4043C??0F93C0C2040032C0C20400', offset = 10 },
};

--[[
* Helper functions
--]]
local function printMsg(msg)
    print(chat.header(addon.name):append(chat.message(msg)));
end

local function printError(msg)
    print(chat.header(addon.name):append(chat.error(msg)));
end

local function printSuccess(msg)
    print(chat.header(addon.name):append(chat.success(msg)));
end

local function findPattern(p)
    local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, 0);
    if addr ~= 0 then
        return addr + p.offset;
    end
    return nil;
end

local function patchAll()
    local count = 0;
    for _, p in ipairs(patterns) do
        local addr = findPattern(p);
        if addr then
            local current = ashita.memory.read_uint8(addr);
            if current == 0x63 then
                ashita.memory.write_uint8(addr, 0x4B);
                printSuccess(string.format('%s: Patched (99->75)', p.name));
                count = count + 1;
            elseif current == 0x4B then
                count = count + 1;
            end
        else
            printError(p.name .. ': Pattern not found');
        end
    end
    return count;
end

local function restoreAll()
    for _, p in ipairs(patterns) do
        local addr = findPattern(p);
        if addr then
            local current = ashita.memory.read_uint8(addr);
            if current == 0x4B then
                ashita.memory.write_uint8(addr, 0x63);
            end
        end
    end
end

local function toggle(name)
    for _, p in ipairs(patterns) do
        if p.name == name then
            local addr = findPattern(p);
            if addr then
                local current = ashita.memory.read_uint8(addr);
                if current == 0x63 then
                    ashita.memory.write_uint8(addr, 0x4B);
                    printSuccess(name .. ': ON (75)');
                elseif current == 0x4B then
                    ashita.memory.write_uint8(addr, 0x63);
                    printMsg(name .. ': OFF (99)');
                end
            else
                printError(name .. ': Pattern not found');
            end
            return;
        end
    end
end

--[[
* Events
--]]
ashita.events.register('load', 'load_cb', function()
    local count = patchAll();
    if count > 0 then
        printSuccess(string.format('Applied %d patch(es). Job Points unlocked at level 75.', count));
    end
end);

ashita.events.register('unload', 'unload_cb', function()
    restoreAll();
end);

ashita.events.register('command', 'command_cb', function(e)
    local args = e.command:args();
    if #args == 0 or not args[1]:ieq('/ujp') then
        return;
    end
    
    e.blocked = true;
    
    if #args == 1 or args[2]:ieq('help') then
        printMsg('Commands: /ujp status | menu | joblist');
        return;
    end
    
    if args[2]:ieq('status') then
        for _, p in ipairs(patterns) do
            local addr = findPattern(p);
            if addr then
                local current = ashita.memory.read_uint8(addr);
                local status = (current == 0x4B) and 'ON (75)' or 'OFF (99)';
                printMsg(string.format('%s: %s', p.name, status));
            else
                printError(p.name .. ': Pattern not found');
            end
        end
        return;
    end
    
    if args[2]:ieq('menu') then
        toggle('MAIN MENU');
        return;
    end
    
    if args[2]:ieq('joblist') then
        toggle('JOB LIST');
        return;
    end
    
    printError('Unknown command. Use /ujp help');
end);
