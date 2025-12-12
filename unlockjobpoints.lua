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
addon.desc    = 'Unlocks the Job Points menu at level 75 via memory patch (for 75-era servers)';
addon.link    = 'https://github.com/kchang4/unlockjobpoints';

require('common');
local chat = require('chat');
local ffi = require('ffi');

-- Configuration
local TARGET_LEVEL = 0x4B;   -- 75 in hex
local ORIGINAL_LEVEL = 0x63; -- 99 in hex

-- Addon state
local state = {
    patches = {}, -- Array of {ptr=address, backup=original_byte, pattern=name}
    gc = nil,     -- Garbage collector for cleanup
    debug = false,
};

-- Known working addresses for specific client versions
-- Format: { [address] = 'purpose' }
local knownAddresses = {
    -- Identified patches:
    [0x045184F7] = 'Job Points Menu',
    [0x0459A605] = 'Unknown (level check)',
    [0x047338F9] = 'Unknown (level check)',
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
* @param {string} patternName - Name of the pattern that matched
* @return {boolean} - True if successful
--]]
local function applyPatch(addr, newByte, patternName)
    -- Read original byte
    local original = ashita.memory.read_uint8(addr);

    -- Store backup with pattern name
    table.insert(state.patches, {
        ptr = addr,
        backup = original,
        pattern = patternName or 'manual',
    });

    -- Write new byte
    ashita.memory.write_uint8(addr, newByte);

    debugPrint(string.format('Patched 0x%08X: 0x%02X -> 0x%02X (%s)', addr, original, newByte, patternName or 'manual'));

    return true;
end

--[[
* Restore all patches
--]]
local function restorePatches()
    for _, patch in ipairs(state.patches) do
        -- Handle both naming conventions (ptr/backup from applyPatch, address/original from per-job)
        local addr = patch.ptr or patch.address;
        local originalByte = patch.backup or patch.original;

        if addr and originalByte then
            ashita.memory.write_uint8(addr, originalByte);
            debugPrint(string.format('Restored 0x%08X: 0x%02X', addr, originalByte));
        end
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

    -- Known patterns for level 99 comparisons
    -- These patterns include the conditional jump after the comparison for accuracy
    -- Pattern format: hex string where ?? = wildcard byte
    -- offset = position of 0x63 byte from pattern start
    local patterns = {
        -- cmp byte ptr [reg+offset], 63h followed by conditional jump
        { pattern = '807E??6372',       offset = 3, name = 'cmp [esi+off],63h; jb' },
        { pattern = '807E??6373',       offset = 3, name = 'cmp [esi+off],63h; jnb' },
        { pattern = '807F??6372',       offset = 3, name = 'cmp [edi+off],63h; jb' },
        { pattern = '807F??6373',       offset = 3, name = 'cmp [edi+off],63h; jnb' },
        { pattern = '807E??630F82',     offset = 3, name = 'cmp [esi+off],63h; jb near' },
        { pattern = '807E??630F83',     offset = 3, name = 'cmp [esi+off],63h; jnb near' },
        -- cmp al, 63h followed by conditional jump
        { pattern = '3C6372',           offset = 1, name = 'cmp al,63h; jb' },
        { pattern = '3C6373',           offset = 1, name = 'cmp al,63h; jnb' },
        { pattern = '3C630F82',         offset = 1, name = 'cmp al,63h; jb near' },
        { pattern = '3C630F83',         offset = 1, name = 'cmp al,63h; jnb near' },
        -- cmp byte ptr [addr], 63h followed by conditional jump
        { pattern = '803D????????6372', offset = 6, name = 'cmp byte ptr [addr],63h; jb' },
        { pattern = '803D????????6373', offset = 6, name = 'cmp byte ptr [addr],63h; jnb' },
        -- movzx then cmp pattern (common for level checks)
        { pattern = '0FB6??3C6372',     offset = 4, name = 'movzx; cmp al,63h; jb' },
        { pattern = '0FB6??3C6373',     offset = 4, name = 'movzx; cmp al,63h; jnb' },
    };

    local patched = {}; -- Track addresses we've already patched

    for _, p in ipairs(patterns) do
        -- Search for all occurrences of this pattern
        local count = 0;
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);

        while addr ~= 0 and count < 20 do
            local patchAddr = addr + p.offset;

            -- Only patch if we haven't patched this address yet
            if not patched[patchAddr] then
                local currentByte = ashita.memory.read_uint8(patchAddr);
                if currentByte == ORIGINAL_LEVEL then
                    applyPatch(patchAddr, TARGET_LEVEL, p.name);
                    patched[patchAddr] = true;
                    patchCount = patchCount + 1;
                end
            end

            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
        end
    end

    return patchCount;
end

--[[
* Find and patch per-job "points_spent > 0" checks
*
* The client checks if job_points_spent > 0 to enable each job in the menu.
* We want to bypass this so all jobs are enabled once you have JOB_BREAKER.
*
* Strategy: Find "cmp word ptr [reg+4], 0" then check if followed by conditional jump
--]]
local function patchPerJobCheck()
    local patchCount = 0;

    -- Search for the cmp instruction only (5 bytes)
    -- Pattern: 66 83 7? 04 00 (cmp word [reg+4], 0)
    -- Then check if byte at offset 5 is a conditional jump (74/75/76/77)
    local patterns = {
        { pattern = '6683780400', name = 'cmp word [eax+4],0' },
        { pattern = '66837E0400', name = 'cmp word [esi+4],0' },
        { pattern = '6683790400', name = 'cmp word [ecx+4],0' },
        { pattern = '66837F0400', name = 'cmp word [edi+4],0' },
        { pattern = '66837B0400', name = 'cmp word [ebx+4],0' },
    };

    local patched = {};

    for _, p in ipairs(patterns) do
        local count = 0;
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);

        while addr ~= 0 and count < 50 do
            -- The conditional jump (if present) is at offset 5
            local patchAddr = addr + 5;
            local jumpByte = ashita.memory.read_uint8(patchAddr);

            -- Check if this is followed by a conditional jump
            -- 74 = JE, 75 = JNE, 76 = JBE, 77 = JA
            local isConditionalJump = (jumpByte == 0x74 or jumpByte == 0x75 or jumpByte == 0x76 or jumpByte == 0x77);

            if not patched[patchAddr] and isConditionalJump then
                local byte2 = ashita.memory.read_uint8(patchAddr + 1);

                -- Store for restore
                table.insert(state.patches, {
                    address = patchAddr,
                    original = jumpByte,
                    patched = 0x90,
                    description = p.name .. ' jump byte 1'
                });
                table.insert(state.patches, {
                    address = patchAddr + 1,
                    original = byte2,
                    patched = 0x90,
                    description = p.name .. ' jump byte 2'
                });

                -- NOP the conditional jump
                ashita.memory.write_uint8(patchAddr, 0x90);
                ashita.memory.write_uint8(patchAddr + 1, 0x90);

                patched[patchAddr] = true;
                patchCount = patchCount + 1;
                printMsg(string.format('Per-job patch at 0x%08X: NOP (was %02X %02X) - %s',
                    patchAddr, jumpByte, byte2, p.name));
            end

            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
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
        { pattern = '807E??63',       name = 'cmp [esi+off],63h' },
        { pattern = '807F??63',       name = 'cmp [edi+off],63h' },
        { pattern = '807B??63',       name = 'cmp [ebx+off],63h' },
        { pattern = '8078??63',       name = 'cmp [eax+off],63h' },
        { pattern = '8079??63',       name = 'cmp [ecx+off],63h' },
        { pattern = '3C63',           name = 'cmp al,63h' },
        { pattern = '803D????????63', name = 'cmp byte ptr [addr],63h' },
        { pattern = '83??63',         name = 'cmp reg,63h' },
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
* Scan for per-job enable patterns (diagnostic tool)
--]]
local function scanForJobPatterns()
    printMsg('Scanning FFXiMain.dll for per-job enable patterns...');

    -- Looking for "cmp word ptr [reg+offset], 0" patterns
    -- These are used to check if job_points_spent > 0
    local patterns = {
        { pattern = '6683??0400', name = 'cmp word [reg+4],0' },
        { pattern = '6683??0600', name = 'cmp word [reg+6],0' },
        { pattern = '6685??04',   name = 'test word [reg+4]' },
        { pattern = '663B??04',   name = 'cmp word reg,[reg+4]' },
        { pattern = '668B??04',   name = 'mov word reg,[reg+4]' },
    };

    local found = 0;
    for _, p in ipairs(patterns) do
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, 0);
        local count = 0;
        while addr ~= 0 and count < 20 do
            -- Read surrounding bytes for context
            local context = '';
            for i = -2, 8 do
                context = context .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
            end
            printMsg(string.format('  %s at 0x%08X: %s', p.name, addr, context));
            found = found + 1;
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
        end
    end

    printMsg(string.format('Scan complete. Found %d potential patterns.', found));
end

--[[
* event: load
* desc : Event called when the addon is being loaded.
--]]
ashita.events.register('load', 'load_cb', function()
    printMsg('v' .. addon.version .. ' loaded');

    -- Try to find and apply level 99 -> 75 patches automatically
    local levelCount = searchAndPatch();

    if levelCount > 0 then
        printSuccess(string.format('Applied %d level patch(es). Job Points menu now unlocks at level 75.', levelCount));
    else
        printError('Could not find level check patterns automatically.');
        printMsg('Use /ujp scan to search for patterns manually.');
    end

    -- Try to find and apply per-job unlock patches
    local perJobCount = patchPerJobCheck();

    if perJobCount > 0 then
        printSuccess(string.format('Applied %d per-job patch(es). All jobs now enabled in JP menu.', perJobCount));
    else
        printMsg('No per-job patches applied (may not be needed or patterns not found).');
    end

    printMsg('Commands: /ujp help');
end);

--[[
* event: unload
* desc : Event called when the addon is being unloaded.
--]]
ashita.events.register('unload', 'unload_cb', function()
    restorePatches();
    printMsg('Addon unloaded, patches restored.');
end);

-- Create a cleanup object to restore patches on crash/force close
state.gc = ffi.gc(ffi.cast('uint8_t*', 0), function()
    restorePatches();
end);

--[[
* event: command
* desc : Event called when the addon is processing a command.
--]]
ashita.events.register('command', 'command_cb', function(e)
    local args = e.command:args();

    if (#args == 0 or (args[1]:lower() ~= '/ujp' and args[1]:lower() ~= '/unlockjobpoints')) then
        return;
    end

    e.blocked = true;

    if (#args == 1 or args[2]:lower() == 'help') then
        printMsg('Commands:');
        printMsg('  /ujp status       - Show current patch status');
        printMsg('  /ujp scan         - Scan for level check patterns');
        printMsg('  /ujp scanjobs     - Scan for per-job enable patterns');
        printMsg('  /ujp patch <hex>  - Manually patch address');
        printMsg('  /ujp restore      - Restore all patches');
        printMsg('  /ujp repatch      - Re-apply automatic patches');
        printMsg('  /ujp test <num>   - Toggle patch #num to identify its purpose');
        printMsg('  /ujp read <hex>   - Read byte at address');
        printMsg('  /ujp debug        - Toggle debug mode');
        return;
    end

    local cmd = args[2]:lower();

    if cmd == 'status' then
        printMsg(string.format('Active patches: %d', #state.patches));
        for i, p in ipairs(state.patches) do
            local purpose = knownAddresses[p.ptr] or 'unknown';
            printMsg(string.format('  %d: 0x%08X [%s] (%s)', i, p.ptr, p.pattern, purpose));
        end
        if #state.patches > 0 then
            printMsg('Use /ujp test <num> to test individual patches.');
        end
    elseif cmd == 'scan' then
        scanForPatterns();
    elseif cmd == 'scanjobs' then
        scanForJobPatterns();
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
        applyPatch(addr, TARGET_LEVEL, 'manual');
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
    elseif cmd == 'test' then
        -- Toggle a specific patch to help identify what it does
        if #args < 3 then
            printError('Usage: /ujp test <patch_number>');
            printMsg('Example: /ujp test 1');
            return;
        end

        local num = tonumber(args[3]);
        if not num or num < 1 or num > #state.patches then
            printError(string.format('Invalid patch number. Valid range: 1-%d', #state.patches));
            return;
        end

        local p = state.patches[num];
        local currentByte = ashita.memory.read_uint8(p.ptr);

        if currentByte == TARGET_LEVEL then
            -- Currently patched, restore original
            ashita.memory.write_uint8(p.ptr, p.backup);
            printMsg(string.format('Patch %d DISABLED (0x%08X now 0x%02X). Zone to test effect.', num, p.ptr, p.backup));
        else
            -- Currently original, apply patch
            ashita.memory.write_uint8(p.ptr, TARGET_LEVEL);
            printMsg(string.format('Patch %d ENABLED (0x%08X now 0x%02X). Zone to test effect.', num, p.ptr, TARGET_LEVEL));
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
