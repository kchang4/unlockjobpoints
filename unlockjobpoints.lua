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
addon.version   = '2.0.0';
addon.desc      = 'Unlocks the Job Points menu at level 75 via memory patch (for 75-era servers)';
addon.link      = 'https://github.com/kchang4/unlockjobpoints';

require('common');
local chat = require('chat');
local ffi = require('ffi');

-- Configuration
local TARGET_LEVEL = 0x4B; -- 75 in hex
local ORIGINAL_LEVEL = 0x63; -- 99 in hex

-- Addon state
local state = {
    patches = {},       -- Array of {ptr=address, backup=original_byte}
    gc = nil,           -- Garbage collector for cleanup
    debug = false,
};

--[[
* Helper function to print messages
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

local function debugPrint(msg)
    if state.debug then
        print(chat.header(addon.name):append(chat.color1(6, '[DEBUG] ' .. msg)));
    end
end

--[[
* Apply a single byte patch
*
* @param {number} addr - The address to patch
* @param {number} newByte - The new byte value
* @return {boolean} - True if successful
--]]
local function applyPatch(addr, newByte)
    -- Read original byte
    local original = ashita.memory.read_uint8(addr);
    
    -- Store backup
    table.insert(state.patches, {
        ptr = addr,
        backup = original,
    });
    
    -- Write new byte
    ashita.memory.write_uint8(addr, newByte);
    
    debugPrint(string.format('Patched 0x%08X: 0x%02X -> 0x%02X', addr, original, newByte));
    
    return true;
end

--[[
* Restore all patches
--]]
local function restorePatches()
    for _, patch in ipairs(state.patches) do
        ashita.memory.write_uint8(patch.ptr, patch.backup);
        debugPrint(string.format('Restored 0x%08X: 0x%02X', patch.ptr, patch.backup));
    end
    state.patches = {};
end

--[[
* Find and patch level 99 comparisons
*
* The client has checks like:
*   if (PTR_status_data.MainJobLevel >= 99u && (flags & 1) != 0)
*
* We need to find these checks and change 99 (0x63) to 75 (0x4B)
--]]
local function searchAndPatch()
    local patchCount = 0;
    
    -- Known patterns for level 99 comparisons in Job Points menu code
    -- These patterns may vary by client version
    
    -- Pattern format: hex string where ?? = wildcard byte
    -- offset = position of 0x63 byte from pattern start
    local patterns = {
        { pattern = '807E??6372', offset = 3, name = 'cmp [esi+off],63h; jb' },
        { pattern = '807E??6373', offset = 3, name = 'cmp [esi+off],63h; jnb' },
        { pattern = '807F??6372', offset = 3, name = 'cmp [edi+off],63h; jb' },
        { pattern = '807F??6373', offset = 3, name = 'cmp [edi+off],63h; jnb' },
        { pattern = '3C6372', offset = 1, name = 'cmp al,63h; jb' },
        { pattern = '3C6373', offset = 1, name = 'cmp al,63h; jnb' },
        { pattern = '803D????????6372', offset = 6, name = 'cmp byte ptr [addr],63h; jb' },
        { pattern = '803D????????6373', offset = 6, name = 'cmp byte ptr [addr],63h; jnb' },
    };
    
    for _, p in ipairs(patterns) do
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, 0);
        if addr ~= 0 then
            local patchAddr = addr + p.offset;
            -- Verify the byte is actually 0x63 (99)
            local currentByte = ashita.memory.read_uint8(patchAddr);
            if currentByte == ORIGINAL_LEVEL then
                applyPatch(patchAddr, TARGET_LEVEL);
                debugPrint(string.format('Found pattern "%s" at 0x%08X', p.name, addr));
                patchCount = patchCount + 1;
            end
        end
    end
    
    return patchCount;
end

--[[
* Scan for all potential level 99 comparisons (diagnostic tool)
--]]
local function scanForPatterns()
    printMsg('Scanning FFXiMain.dll for level 99 comparisons...');
    
    local patterns = {
        { pattern = '807E??63', name = 'cmp [esi+off],63h' },
        { pattern = '807F??63', name = 'cmp [edi+off],63h' },
        { pattern = '807B??63', name = 'cmp [ebx+off],63h' },
        { pattern = '8078??63', name = 'cmp [eax+off],63h' },
        { pattern = '8079??63', name = 'cmp [ecx+off],63h' },
        { pattern = '3C63', name = 'cmp al,63h' },
        { pattern = '803D????????63', name = 'cmp byte ptr [addr],63h' },
        { pattern = '83??63', name = 'cmp reg,63h' },
    };
    
    local found = 0;
    for _, p in ipairs(patterns) do
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, 0);
        local count = 0;
        while addr ~= 0 and count < 10 do
            printMsg(string.format('  %s at 0x%08X', p.name, addr));
            found = found + 1;
            count = count + 1;
            -- Search for next occurrence
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
        end
    end
    
    printMsg(string.format('Scan complete. Found %d potential patterns.', found));
end

--[[
* event: load
* desc : Event called when the addon is being loaded.
--]]
ashita.events.register('load', 'load_cb', function ()
    printMsg('v' .. addon.version .. ' loaded');
    
    -- Try to find and apply patches automatically
    local count = searchAndPatch();
    
    if count > 0 then
        printSuccess(string.format('Applied %d memory patch(es). Job Points menu now unlocks at level 75.', count));
    else
        printError('Could not find level check patterns automatically.');
        printMsg('Use /ujp scan to search for patterns manually.');
        printMsg('Use /ujp patch <address> to patch a specific address.');
    end
    
    printMsg('Commands: /ujp help');
end);

--[[
* event: unload
* desc : Event called when the addon is being unloaded.
--]]
ashita.events.register('unload', 'unload_cb', function ()
    restorePatches();
    printMsg('Addon unloaded, patches restored.');
end);

-- Create a cleanup object to restore patches on crash/force close
state.gc = ffi.gc(ffi.cast('uint8_t*', 0), function ()
    restorePatches();
end);

--[[
* event: command
* desc : Event called when the addon is processing a command.
--]]
ashita.events.register('command', 'command_cb', function (e)
    local args = e.command:args();
    
    if (#args == 0 or (args[1]:lower() ~= '/ujp' and args[1]:lower() ~= '/unlockjobpoints')) then
        return;
    end
    
    e.blocked = true;
    
    if (#args == 1 or args[2]:lower() == 'help') then
        printMsg('Commands:');
        printMsg('  /ujp status      - Show current patch status');
        printMsg('  /ujp scan        - Scan for level check patterns');
        printMsg('  /ujp patch <hex> - Manually patch address (e.g., /ujp patch 12345678)');
        printMsg('  /ujp restore     - Restore all patches');
        printMsg('  /ujp repatch     - Re-apply automatic patches');
        printMsg('  /ujp read <hex>  - Read byte at address');
        printMsg('  /ujp debug       - Toggle debug mode');
        return;
    end
    
    local cmd = args[2]:lower();
    
    if cmd == 'status' then
        printMsg(string.format('Active patches: %d', #state.patches));
        for i, p in ipairs(state.patches) do
            printMsg(string.format('  %d: 0x%08X (was 0x%02X, now 0x%02X)', i, p.ptr, p.backup, TARGET_LEVEL));
        end
        
    elseif cmd == 'scan' then
        scanForPatterns();
        
    elseif cmd == 'patch' then
        if #args < 3 then
            printError('Usage: /ujp patch <address>');
            printMsg('Example: /ujp patch 12345678');
            return;
        end
        
        local addr = tonumber(args[3], 16);
        if not addr or addr == 0 then
            printError('Invalid address: ' .. args[3]);
            return;
        end
        
        local currentByte = ashita.memory.read_uint8(addr);
        applyPatch(addr, TARGET_LEVEL);
        printSuccess(string.format('Patched 0x%08X: 0x%02X -> 0x%02X', addr, currentByte, TARGET_LEVEL));
        
    elseif cmd == 'restore' then
        local count = #state.patches;
        restorePatches();
        printSuccess(string.format('Restored %d patch(es).', count));
        
    elseif cmd == 'repatch' then
        restorePatches();
        local count = searchAndPatch();
        if count > 0 then
            printSuccess(string.format('Re-applied %d patch(es).', count));
        else
            printError('Could not find patterns to patch.');
        end
        
    elseif cmd == 'read' then
        if #args < 3 then
            printError('Usage: /ujp read <address>');
            return;
        end
        
        local addr = tonumber(args[3], 16);
        if not addr or addr == 0 then
            printError('Invalid address: ' .. args[3]);
            return;
        end
        
        local byte = ashita.memory.read_uint8(addr);
        printMsg(string.format('0x%08X = 0x%02X (%d)', addr, byte, byte));
        
    elseif cmd == 'debug' then
        state.debug = not state.debug;
        printMsg(string.format('Debug mode: %s', state.debug and 'ON' or 'OFF'));
        
    else
        printError('Unknown command: ' .. cmd);
        printMsg('Use /ujp help for command list.');
    end
end);
