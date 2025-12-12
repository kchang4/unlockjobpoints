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

-- Job name lookup table
local jobNames = {
    [0] = 'NON',
    [1] = 'WAR',
    [2] = 'MNK',
    [3] = 'WHM',
    [4] = 'BLM',
    [5] = 'RDM',
    [6] = 'THF',
    [7] = 'PLD',
    [8] = 'DRK',
    [9] = 'BST',
    [10] = 'BRD',
    [11] = 'RNG',
    [12] = 'SAM',
    [13] = 'NIN',
    [14] = 'DRG',
    [15] = 'SMN',
    [16] = 'BLU',
    [17] = 'COR',
    [18] = 'PUP',
    [19] = 'DNC',
    [20] = 'SCH',
    [21] = 'GEO',
    [22] = 'RUN',
};

-- Addon state
local state = {
    patches = {},          -- Array of {ptr=address, backup=original_byte, pattern=name}
    gc = nil,              -- Garbage collector for cleanup
    debug = false,
    jobLevelsAddr = nil,   -- Address of the job levels array in memory (DEPRECATED - causes visual bug)
    autoSetLevels = false, -- DISABLED - causes visual bug showing Lv.99
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
* Find the job levels array in memory by searching for a pattern
* @return {number|nil} - Address if found, nil otherwise
--]]
local function findJobLevelsAddress()
    local player = AshitaCore:GetMemoryManager():GetPlayer();
    if not player then
        return nil;
    end

    -- Build a search pattern from current job levels (jobs 1-10)
    local patternStr = '';
    for jobId = 1, 10 do
        local level = player:GetJobLevel(jobId);
        patternStr = patternStr .. string.format('%02X', level);
    end

    -- Search in FFXiMain.dll
    local addr = ashita.memory.find('FFXiMain.dll', 0, patternStr, 0, 0);
    if addr ~= 0 then
        -- The pattern starts at job 1, so subtract 1 to get base (job 0)
        return addr - 1;
    end

    return nil;
end

--[[
* Set all job levels to 99 at the stored address
* @param {boolean} silent - If true, don't print messages
* @return {number} - Number of jobs modified
--]]
local function setAllJobLevels99(silent)
    if not state.jobLevelsAddr then
        -- Try to find it
        state.jobLevelsAddr = findJobLevelsAddress();
        if not state.jobLevelsAddr then
            if not silent then
                printError('Job levels address not found. Use /ujp setjobs99 first.');
            end
            return 0;
        end
        if not silent then
            debugPrint(string.format('Found job levels at 0x%08X', state.jobLevelsAddr));
        end
    end

    local modified = 0;
    for i = 0, 22 do
        local current = ashita.memory.read_uint8(state.jobLevelsAddr + i);
        if current > 0 and current < 99 then
            ashita.memory.write_uint8(state.jobLevelsAddr + i, 99);
            modified = modified + 1;
        end
    end

    if modified > 0 and not silent then
        debugPrint(string.format('Set %d job levels to 99', modified));
    end

    return modified;
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
*   if (job_levels[jobId] >= 99) // per-job check
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
        { pattern = '8078??6372',       offset = 3, name = 'cmp [eax+off],63h; jb' },
        { pattern = '8078??6373',       offset = 3, name = 'cmp [eax+off],63h; jnb' },
        { pattern = '8079??6372',       offset = 3, name = 'cmp [ecx+off],63h; jb' },
        { pattern = '8079??6373',       offset = 3, name = 'cmp [ecx+off],63h; jnb' },
        { pattern = '807A??6372',       offset = 3, name = 'cmp [edx+off],63h; jb' },
        { pattern = '807A??6373',       offset = 3, name = 'cmp [edx+off],63h; jnb' },
        { pattern = '807B??6372',       offset = 3, name = 'cmp [ebx+off],63h; jb' },
        { pattern = '807B??6373',       offset = 3, name = 'cmp [ebx+off],63h; jnb' },
        -- cmp al, 63h followed by conditional jump
        { pattern = '3C6372',           offset = 1, name = 'cmp al,63h; jb' },
        { pattern = '3C6373',           offset = 1, name = 'cmp al,63h; jnb' },
        { pattern = '3C630F82',         offset = 1, name = 'cmp al,63h; jb near' },
        { pattern = '3C630F83',         offset = 1, name = 'cmp al,63h; jnb near' },
        -- cmp cl/dl/bl, 63h (other register comparisons)
        { pattern = '80F96372',         offset = 2, name = 'cmp cl,63h; jb' },
        { pattern = '80F96373',         offset = 2, name = 'cmp cl,63h; jnb' },
        { pattern = '80FA6372',         offset = 2, name = 'cmp dl,63h; jb' },
        { pattern = '80FA6373',         offset = 2, name = 'cmp dl,63h; jnb' },
        { pattern = '80FB6372',         offset = 2, name = 'cmp bl,63h; jb' },
        { pattern = '80FB6373',         offset = 2, name = 'cmp bl,63h; jnb' },
        -- cmp byte ptr [addr], 63h followed by conditional jump
        { pattern = '803D????????6372', offset = 6, name = 'cmp byte ptr [addr],63h; jb' },
        { pattern = '803D????????6373', offset = 6, name = 'cmp byte ptr [addr],63h; jnb' },
        -- movzx then cmp pattern (common for level checks)
        { pattern = '0FB6??3C6372',     offset = 4, name = 'movzx; cmp al,63h; jb' },
        { pattern = '0FB6??3C6373',     offset = 4, name = 'movzx; cmp al,63h; jnb' },
        -- cmp reg, 63h (32-bit register compare with immediate)
        { pattern = '83F86372',         offset = 2, name = 'cmp eax,63h; jb' },
        { pattern = '83F86373',         offset = 2, name = 'cmp eax,63h; jnb' },
        { pattern = '83F9637?',         offset = 2, name = 'cmp ecx,63h; j?' },
        { pattern = '83FA637?',         offset = 2, name = 'cmp edx,63h; j?' },
        { pattern = '83FB637?',         offset = 2, name = 'cmp ebx,63h; j?' },
        { pattern = '83FE637?',         offset = 2, name = 'cmp esi,63h; j?' },
        { pattern = '83FF637?',         offset = 2, name = 'cmp edi,63h; j?' },
        -- Array-indexed level checks: cmp byte ptr [base+reg], 63h
        -- These are used for per-job level checks like: if (job_levels[jobId] >= 99)
        { pattern = '3A??6372',         offset = 2, name = 'cmp reg,[reg+off]; jb (val=63h)' },
        { pattern = '3A??6373',         offset = 2, name = 'cmp reg,[reg+off]; jnb (val=63h)' },
        -- cmp byte ptr [reg+reg+offset], 63h - scaled array access
        { pattern = '807C??006372',     offset = 4, name = 'cmp [reg+reg+0],63h; jb' },
        { pattern = '807C??006373',     offset = 4, name = 'cmp [reg+reg+0],63h; jnb' },
        { pattern = '807C????6372',     offset = 4, name = 'cmp [reg+reg+off],63h; jb' },
        { pattern = '807C????6373',     offset = 4, name = 'cmp [reg+reg+off],63h; jnb' },
        -- More general patterns without specific jumps (aggressive)
        { pattern = '3C6374',           offset = 1, name = 'cmp al,63h; je' },
        { pattern = '3C6375',           offset = 1, name = 'cmp al,63h; jne' },
        { pattern = '3C6376',           offset = 1, name = 'cmp al,63h; jbe' },
        { pattern = '3C6377',           offset = 1, name = 'cmp al,63h; ja' },
        { pattern = '3C637C',           offset = 1, name = 'cmp al,63h; jl' },
        { pattern = '3C637D',           offset = 1, name = 'cmp al,63h; jge' },
        { pattern = '3C637E',           offset = 1, name = 'cmp al,63h; jle' },
        { pattern = '3C637F',           offset = 1, name = 'cmp al,63h; jg' },
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
* Strategy: Find "cmp word ptr [reg+X], 0" then check if followed by conditional jump
--]]
local function patchPerJobCheck()
    local patchCount = 0;

    -- Search for the cmp instruction only (5 bytes)
    -- Pattern: 66 83 7? XX 00 (cmp word [reg+XX], 0)
    -- Check offset +4 (points) and +6 (points_spent in struct)
    -- Then check if byte at offset 5 is a conditional jump (74/76)
    local patterns = {
        -- Offset +4 patterns
        { pattern = '6683780400', name = 'cmp word [eax+4],0' },
        { pattern = '66837E0400', name = 'cmp word [esi+4],0' },
        { pattern = '6683790400', name = 'cmp word [ecx+4],0' },
        { pattern = '66837F0400', name = 'cmp word [edi+4],0' },
        { pattern = '66837B0400', name = 'cmp word [ebx+4],0' },
        { pattern = '66837A0400', name = 'cmp word [edx+4],0' },
        -- Offset +6 patterns (points_spent may be here too)
        { pattern = '6683780600', name = 'cmp word [eax+6],0' },
        { pattern = '66837E0600', name = 'cmp word [esi+6],0' },
        { pattern = '6683790600', name = 'cmp word [ecx+6],0' },
        { pattern = '66837F0600', name = 'cmp word [edi+6],0' },
        { pattern = '66837D0600', name = 'cmp word [ebp+6],0' },
        { pattern = '66837A0600', name = 'cmp word [edx+6],0' },
    };

    local patched = {};
    local foundAny = false;

    for _, p in ipairs(patterns) do
        local count = 0;
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);

        while addr ~= 0 and count < 50 do
            foundAny = true;
            -- The conditional jump (if present) is at offset 5
            local patchAddr = addr + 5;
            local jumpByte = ashita.memory.read_uint8(patchAddr);

            -- Only patch jumps that SKIP when points_spent is 0/low:
            -- 74 = JE (jump if equal to 0) - skip enable when 0
            -- 76 = JBE (jump if below or equal) - skip enable when <= 0
            -- Do NOT patch:
            -- 75 = JNE (jump if NOT equal) - this is the ENABLE path!
            -- 77 = JA (jump if above) - this is the ENABLE path!
            local shouldPatch = (jumpByte == 0x74 or jumpByte == 0x76);

            if not patched[patchAddr] and shouldPatch then
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
            else
                -- Debug: show what we found but didn't patch
                debugPrint(string.format('Found %s at 0x%08X, next byte is %02X (not patching)',
                    p.name, addr, jumpByte));
            end

            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
        end
    end

    if not foundAny then
        debugPrint('No cmp word patterns found at all - pattern search may be failing');
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
        { pattern = '80F963',         name = 'cmp cl,63h' },
        { pattern = '80FA63',         name = 'cmp dl,63h' },
        { pattern = '80FB63',         name = 'cmp bl,63h' },
    };

    local found = 0;
    for _, p in ipairs(patterns) do
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, 0);
        local count = 0;
        while addr ~= 0 and count < 15 do
            -- Read bytes before and after to show context
            local context = '';
            for i = -4, 8 do
                context = context .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
            end
            printMsg(string.format('  %s at 0x%08X: %s', p.name, addr, context));
            found = found + 1;
            count = count + 1;
            -- Search for next occurrence
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
        end
    end

    printMsg(string.format('Scan complete. Found %d potential patterns.', found));
end

--[[
* Scan for ALL level 99 references (aggressive search)
--]]
local function scanAll99()
    printMsg('Scanning FFXiMain.dll for ALL level 99 (0x63) comparisons...');
    printMsg('This may find many false positives. Look for patterns near JP menu code.');

    -- Very broad patterns - just looking for 0x63 in comparison contexts
    local patterns = {
        -- Any cmp byte with 0x63
        { pattern = '80??63', offset = 2, name = 'cmp byte,63h' },
        { pattern = '3C63',   offset = 1, name = 'cmp al,63h' },
        { pattern = '80F963', offset = 2, name = 'cmp cl,63h' },
        { pattern = '80FA63', offset = 2, name = 'cmp dl,63h' },
        { pattern = '83F863', offset = 2, name = 'cmp eax,63h' },
        { pattern = '83F963', offset = 2, name = 'cmp ecx,63h' },
        { pattern = '83FA63', offset = 2, name = 'cmp edx,63h' },
        { pattern = '83FE63', offset = 2, name = 'cmp esi,63h' },
        { pattern = '83FF63', offset = 2, name = 'cmp edi,63h' },
    };

    local found = 0;
    local results = {};

    for _, p in ipairs(patterns) do
        local count = 0;
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);

        while addr ~= 0 and count < 30 do
            -- Check if this looks like a level check (followed by conditional jump)
            local nextByte = ashita.memory.read_uint8(addr + #p.pattern / 2);
            local isJump = (nextByte >= 0x70 and nextByte <= 0x7F) or (nextByte == 0x0F);

            local context = '';
            for i = -2, 6 do
                context = context .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
            end

            if isJump then
                printMsg(string.format('  [JUMP] %s at 0x%08X: %s', p.name, addr, context));
            else
                debugPrint(string.format('  [----] %s at 0x%08X: %s', p.name, addr, context));
            end

            found = found + 1;
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
        end
    end

    printMsg(string.format('Scan complete. Found %d patterns (showing those with jumps).', found));
    printMsg('Enable debug mode to see all patterns: /ujp debug');
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

    -- Try to find the job levels address and set all to 99
    if state.autoSetLevels then
        state.jobLevelsAddr = findJobLevelsAddress();
        if state.jobLevelsAddr then
            local modified = setAllJobLevels99(true);
            if modified > 0 then
                printSuccess(string.format('Auto-set %d job levels to 99 (addr: 0x%08X)', modified, state.jobLevelsAddr));
            end
        else
            printMsg('Job levels address not found yet. Will try after packets arrive.');
        end
    end

    printMsg('Auto-set job levels: ' .. (state.autoSetLevels and 'ON' or 'OFF'));
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
* event: packet_in
* desc : Intercept incoming packets to modify job points data
*
* Packet 0x063 is "miscdata" with various subtypes.
* Subtype 0x05 is JobPoints Totals data containing:
*   - offset 0x04: subtype (1 byte = 0x05)
*   - offset 0x0C onwards: job data (6 bytes per job: capacityPoints u16, currentJp u16, totalJpSpent u16)
*   - Based on tCrossBar: playerData.JobPoints[i].Total = struct.unpack('H', e.data, 0x0C + 0x04 + (6 * i) + 1);
*     Which is offset 0x10 + (6*i) for totalJpSpent (the +4 is to get to the Total field within entry)
*
* Packet 0x08D is JobPoints Categories (individual upgrade counts per job)
*   - Contains specific upgrade counts that may affect menu availability
*
* Packet 0x061 is Char Stats containing job levels for all jobs.
*   - We modify all job levels to 99 so the per-job JP menu checks pass.
*
* We modify totalJpSpent to 500 for any job under that threshold to enable it in the menu.
--]]
ashita.events.register('packet_in', 'ujp_packet_in_cb', function(e)
    -- Log packets we receive if debug is on
    if state.debug and (e.id == 0x0063 or e.id == 0x008D or e.id == 0x0061) then
        local ptr = ffi.cast('uint8_t*', e.data_modified_raw);
        local hexDump = '';
        for i = 0, math.min(31, e.size - 1) do
            hexDump = hexDump .. string.format('%02X ', ptr[i]);
        end
        printMsg(string.format('Packet 0x%04X (size=%d): %s', e.id, e.size, hexDump));
    end

    -- Packet 0x061 = Char Stats (contains job levels)
    -- We need to set all job levels to 99 for the JP menu per-job checks
    if e.id == 0x0061 then
        local ptr = ffi.cast('uint8_t*', e.data_modified_raw);

        printMsg(string.format('*** Intercepted Char Stats packet (0x061) size=%d ***', e.size));

        -- Dump first 64 bytes to see structure
        if state.debug then
            local hexDump = '';
            for i = 0, math.min(63, e.size - 1) do
                hexDump = hexDump .. string.format('%02X ', ptr[i]);
                if (i + 1) % 16 == 0 then
                    debugPrint(string.format('  0x%02X: %s', i - 15, hexDump));
                    hexDump = '';
                end
            end
        end

        -- Try multiple possible offsets for job levels array
        -- Different sources report different offsets
        local possibleOffsets = {
            0x14, -- Some sources say here
            0x44, -- Other sources say here
            0x60, -- Also possible
        };

        -- Main job level is at 0x0D, let's verify that first
        local mainJobLevel = ptr[0x0D];
        printMsg(string.format('  Main job level at 0x0D: %d', mainJobLevel));

        -- Force set main job level to 99
        if mainJobLevel > 0 and mainJobLevel < 99 then
            ptr[0x0D] = 99;
            printMsg('  -> Set main job level to 99');
        end

        -- Sub job level is at 0x0F
        local subJobLevel = ptr[0x0F];
        if subJobLevel > 0 and subJobLevel < 99 then
            ptr[0x0F] = 99;
            printMsg(string.format('  -> Set sub job level (%d -> 99)', subJobLevel));
        end

        -- After packet processing, re-apply level 99 to client's cached job levels
        -- The packet will have overwritten our previous modifications
        if state.autoSetLevels then
            -- Use a short delay to let the packet finish processing
            ashita.tasks.once(0.1, function()
                local modified = setAllJobLevels99(true);
                if modified > 0 then
                    debugPrint(string.format('Auto-set %d job levels to 99 after packet', modified));
                end
            end);
        end
    end

    -- Packet 0x063 = miscdata
    if e.id == 0x0063 then
        local ptr = ffi.cast('uint8_t*', e.data_modified_raw);
        local subtype = ptr[0x04];

        debugPrint(string.format('Packet 0x063 subtype=%d (0x%02X)', subtype, subtype));

        -- Subtype 0x05 = Job Points Totals data
        if subtype == 0x05 then
            printMsg('*** Intercepted Job Points TOTALS packet (0x063 subtype 0x05) ***');

            -- Based on tCrossBar analysis:
            -- playerData.JobPoints[i].Total = struct.unpack('H', e.data, 0x0C + 0x04 + (6 * i) + 1);
            -- In 0-based terms: offset = 0x0C + 0x04 + (6 * i) = 0x10 + (6 * i) for totalJpSpent
            -- But wait - they're reading the TOTAL which is at +4 within the 6-byte entry
            -- Entry layout: capacityPoints(2), currentJp(2), totalJpSpent(2)
            -- So Total is at offset 4 within entry (totalJpSpent)
            -- Base offset for job data is 0x0C (after 4-byte header + 8 bytes misc = 0x0C)

            local jobDataOffset = 0x0C;   -- Start of job array
            local jobEntrySize = 6;       -- Each entry is 6 bytes
            local totalJpSpentOffset = 4; -- totalJpSpent is at offset 4 within entry

            local modified = 0;
            for jobId = 1, 22 do
                local entryOffset = jobDataOffset + (jobId * jobEntrySize);
                local spentOffset = entryOffset + totalJpSpentOffset;

                -- Read current values for debugging
                local cpLow = ptr[entryOffset];
                local cpHigh = ptr[entryOffset + 1];
                local capacityPoints = cpLow + (cpHigh * 256);

                local jpLow = ptr[entryOffset + 2];
                local jpHigh = ptr[entryOffset + 3];
                local currentJp = jpLow + (jpHigh * 256);

                local spentLow = ptr[spentOffset];
                local spentHigh = ptr[spentOffset + 1];
                local totalSpent = spentLow + (spentHigh * 256);

                if state.debug and jobId <= 5 then
                    debugPrint(string.format('  Job %d @ 0x%02X: CP=%d, JP=%d, Spent=%d',
                        jobId, entryOffset, capacityPoints, currentJp, totalSpent));
                end

                if totalSpent < 500 then
                    -- Set to 500 to enable the job in the menu
                    -- (1 wasn't enough - client may check for minimum threshold)
                    -- 500 = 0x01F4 in little-endian: F4 01
                    ptr[spentOffset] = 0xF4;
                    ptr[spentOffset + 1] = 0x01;
                    modified = modified + 1;
                end
            end

            if modified > 0 then
                printMsg(string.format('Modified %d jobs: totalJpSpent -> 500', modified));
            else
                printMsg('No jobs needed modification (all have spent >= 500)');
            end
        end
    end

    -- Packet 0x08D = Job Points Categories
    if e.id == 0x008D then
        local ptr = ffi.cast('uint8_t*', e.data_modified_raw);
        local jobPointCount = (e.size / 4) - 1;

        debugPrint(string.format('*** Received Job Points CATEGORIES packet (0x08D), entries: %d ***', jobPointCount));

        -- Dump first few entries to understand structure
        if state.debug then
            for i = 0, math.min(7, jobPointCount - 1) do
                local offset = 4 + (i * 4);
                local b0, b1, b2, b3 = ptr[offset], ptr[offset + 1], ptr[offset + 2], ptr[offset + 3];
                debugPrint(string.format('  Entry %d: %02X %02X %02X %02X', i, b0, b1, b2, b3));
            end
        end

        -- The structure per tCrossBar (big-endian bit unpacking):
        -- bits 0-4: index (category index within job, 0-31)
        -- bits 5-15: job (job ID)
        -- bits 26-31: count (upgrade count)
        --
        -- For each entry where count is 0, we could set it to 1 to indicate JP spent
        -- But this is complex bit manipulation. Instead, let's try the simpler approach
        -- of just ensuring each job has at least one entry with count > 0

        local modified = 0;
        for i = 0, jobPointCount - 1 do
            local offset = 4 + (i * 4);
            -- Read last byte which contains count in bits 2-7
            local lastByte = ptr[offset + 3];
            local count = bit.rshift(lastByte, 2);

            if count == 0 then
                -- Set count to 1 (shift left by 2 to put in correct position)
                ptr[offset + 3] = bit.bor(bit.band(lastByte, 0x03), bit.lshift(1, 2));
                modified = modified + 1;
            end
        end

        if modified > 0 then
            printMsg(string.format('Modified %d JP category entries: count 0 -> 1', modified));
        end
    end
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
        printMsg('  /ujp scanall      - Aggressive scan for ALL 99 comparisons');
        printMsg('  /ujp nearjp       - Scan for 99 checks near JP menu code');
        printMsg('  /ujp rawscan      - Show ALL 0x63 bytes near JP menu');
        printMsg('  /ujp patchnear    - Patch all 99 checks near JP menu');
        printMsg('  /ujp patchall     - Aggressively patch ALL 99 comparisons');
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
        printMsg(string.format('Auto-set job levels: %s', state.autoSetLevels and 'ON' or 'OFF'));
        printMsg(string.format('Job levels address: %s',
            state.jobLevelsAddr and string.format('0x%08X', state.jobLevelsAddr) or 'not found'));
        printMsg(string.format('Debug mode: %s', state.debug and 'ON' or 'OFF'));
        if #state.patches > 0 then
            printMsg('Patches:');
            for i, p in ipairs(state.patches) do
                local purpose = knownAddresses[p.ptr] or 'unknown';
                printMsg(string.format('  %d: 0x%08X [%s] (%s)', i, p.ptr, p.pattern, purpose));
            end
            printMsg('Use /ujp test <num> to test individual patches.');
        end
    elseif cmd == 'auto' then
        state.autoSetLevels = not state.autoSetLevels;
        printMsg(string.format('Auto-set job levels: %s', state.autoSetLevels and 'ON' or 'OFF'));
        if state.autoSetLevels then
            -- Apply immediately
            local modified = setAllJobLevels99(false);
            if modified > 0 then
                printSuccess(string.format('Set %d job levels to 99', modified));
            end
        end
    elseif cmd == 'scan' then
        scanForPatterns();
    elseif cmd == 'scanall' then
        scanAll99();
    elseif cmd == 'scanjobs' then
        scanForJobPatterns();
    elseif cmd == 'patchall' then
        -- Aggressively patch ALL level 99 comparisons in FFXiMain.dll
        printMsg('Aggressively patching ALL level 99 comparisons...');

        local patterns = {
            { pattern = '3C63',   offset = 1, name = 'cmp al,63h' },
            { pattern = '80F963', offset = 2, name = 'cmp cl,63h' },
            { pattern = '80FA63', offset = 2, name = 'cmp dl,63h' },
            { pattern = '80FB63', offset = 2, name = 'cmp bl,63h' },
            { pattern = '83F863', offset = 2, name = 'cmp eax,63h' },
            { pattern = '83F963', offset = 2, name = 'cmp ecx,63h' },
            { pattern = '83FA63', offset = 2, name = 'cmp edx,63h' },
            { pattern = '83FB63', offset = 2, name = 'cmp ebx,63h' },
            { pattern = '83FE63', offset = 2, name = 'cmp esi,63h' },
            { pattern = '83FF63', offset = 2, name = 'cmp edi,63h' },
        };

        local patched = {};
        local totalCount = 0;

        for _, p in ipairs(patterns) do
            local count = 0;
            local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);

            while addr ~= 0 and count < 50 do
                local patchAddr = addr + p.offset;

                if not patched[patchAddr] then
                    local currentByte = ashita.memory.read_uint8(patchAddr);
                    if currentByte == ORIGINAL_LEVEL then
                        applyPatch(patchAddr, TARGET_LEVEL, p.name);
                        patched[patchAddr] = true;
                        totalCount = totalCount + 1;
                        printMsg(string.format('  Patched 0x%08X (%s)', patchAddr, p.name));
                    end
                end

                count = count + 1;
                addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
            end
        end

        printSuccess(string.format('Patched %d additional level 99 comparisons.', totalCount));
        printMsg('Now try opening the Job Points menu.');
    elseif cmd == 'nearjp' then
        -- Search for level 99 comparisons near the known JP menu address
        -- The per-job check is likely in the same function or nearby
        local baseAddr = 0x045184F7; -- Known JP menu address
        local searchRange = 0x2000;  -- Search ±8KB around this address

        printMsg(string.format('Searching for level 99 (0x63) bytes near 0x%08X...', baseAddr));

        local found = 0;
        for offset = -searchRange, searchRange do
            local addr = baseAddr + offset;
            local byte = ashita.memory.read_uint8(addr);

            if byte == 0x63 then
                -- Read context around this address
                local context = '';
                for i = -6, 6 do
                    context = context .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
                end

                -- Check bytes before this 0x63
                local prev1 = ashita.memory.read_uint8(addr - 1);
                local prev2 = ashita.memory.read_uint8(addr - 2);
                local prev3 = ashita.memory.read_uint8(addr - 3);
                local prev4 = ashita.memory.read_uint8(addr - 4);
                local next1 = ashita.memory.read_uint8(addr + 1);

                local isLikelyCompare = false;
                local patternType = '';

                -- 3C 63 = cmp al, 63h (prev1 = 3C)
                if prev1 == 0x3C then
                    isLikelyCompare = true;
                    patternType = 'cmp al,63h';
                -- 80 FX 63 = cmp Xl, 63h
                elseif prev2 == 0x80 and prev1 >= 0xF8 and prev1 <= 0xFF then
                    isLikelyCompare = true;
                    patternType = string.format('cmp %s,63h', 
                        ({[0xF8]='al',[0xF9]='cl',[0xFA]='dl',[0xFB]='bl'})[prev1] or 'reg');
                -- 83 FX 63 = cmp eXx, 63h
                elseif prev2 == 0x83 and prev1 >= 0xF8 and prev1 <= 0xFF then
                    isLikelyCompare = true;
                    patternType = 'cmp e??,63h';
                -- 80 7X YY 63 = cmp byte ptr [reg+YY], 63h
                elseif prev3 == 0x80 and prev2 >= 0x78 and prev2 <= 0x7F then
                    isLikelyCompare = true;
                    patternType = string.format('cmp [reg+%02X],63h', prev1);
                -- 80 3X YY 63 = cmp byte ptr [reg+YY], 63h (different encoding)
                elseif prev3 == 0x80 and prev2 >= 0x38 and prev2 <= 0x3F then
                    isLikelyCompare = true;
                    patternType = 'cmp [reg],63h';
                -- 80 7C XX YY 63 = cmp byte ptr [reg+reg*scale+off], 63h
                elseif prev4 == 0x80 and prev3 == 0x7C then
                    isLikelyCompare = true;
                    patternType = 'cmp [reg+reg+off],63h';
                -- 38 XX 63 or 3A XX 63 - cmp with memory operand
                elseif prev2 == 0x38 or prev2 == 0x3A or prev2 == 0x3B then
                    isLikelyCompare = true;
                    patternType = 'cmp reg,mem';
                end

                -- Check if next byte is a jump instruction
                local isJump = (next1 >= 0x70 and next1 <= 0x7F) or next1 == 0x0F;

                if isLikelyCompare then
                    local jumpStr = isJump and ' [JUMP]' or '';
                    printMsg(string.format('  0x%08X: %s%s - %s', addr, patternType, jumpStr, context));
                    found = found + 1;
                end
            end
        end

        printMsg(string.format('Found %d potential level 99 comparisons near JP menu code.', found));
        if found == 0 then
            printMsg('No patterns found. Try /ujp rawscan to see ALL 0x63 bytes.');
        end
    elseif cmd == 'rawscan' then
        -- Raw scan: show ALL 0x63 bytes near JP menu code
        local baseAddr = 0x045184F7;
        local searchRange = 0x2000;
        
        printMsg(string.format('Raw scan for ALL 0x63 bytes near 0x%08X...', baseAddr));
        
        local found = 0;
        for offset = -searchRange, searchRange do
            local addr = baseAddr + offset;
            local byte = ashita.memory.read_uint8(addr);

            if byte == 0x63 then
                local context = '';
                for i = -6, 6 do
                    context = context .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
                end
                printMsg(string.format('  0x%08X: %s', addr, context));
                found = found + 1;
            end
        end
        
        printMsg(string.format('Found %d occurrences of 0x63.', found));
    elseif cmd == 'patchnear' then
        -- Patch ALL level 99 comparisons near the JP menu code
        local baseAddr = 0x045184F7;
        local searchRange = 0x2000;

        printMsg(string.format('Patching all level 99 comparisons near 0x%08X...', baseAddr));

        local patched = 0;
        for offset = -searchRange, searchRange do
            local addr = baseAddr + offset;
            local byte = ashita.memory.read_uint8(addr);

            if byte == 0x63 then
                local prevByte = ashita.memory.read_uint8(addr - 1);
                local prev2Byte = ashita.memory.read_uint8(addr - 2);
                local prev3Byte = ashita.memory.read_uint8(addr - 3);

                local isLikelyCompare = false;

                -- 3C 63 = cmp al, 63h
                if prev2Byte == 0x3C then
                    isLikelyCompare = true;
                    -- 80 FX 63 = cmp Xl, 63h
                elseif prev2Byte == 0x80 and (prevByte >= 0xF8 and prevByte <= 0xFF) then
                    isLikelyCompare = true;
                    -- 83 FX 63 = cmp eXx, 63h
                elseif prev2Byte == 0x83 and (prevByte >= 0xF8 and prevByte <= 0xFF) then
                    isLikelyCompare = true;
                    -- 80 7X XX 63 = cmp byte ptr [reg+XX], 63h
                elseif prev3Byte == 0x80 and (prev2Byte >= 0x78 and prev2Byte <= 0x7F) then
                    isLikelyCompare = true;
                    -- 80 7C XX YY 63 = cmp byte ptr [reg+reg*scale+off], 63h
                elseif ashita.memory.read_uint8(addr - 4) == 0x80 and prev3Byte == 0x7C then
                    isLikelyCompare = true;
                end

                if isLikelyCompare then
                    applyPatch(addr, TARGET_LEVEL, 'nearjp');
                    patched = patched + 1;
                    printMsg(string.format('  Patched 0x%08X: 0x63 -> 0x4B', addr));
                end
            end
        end

        printSuccess(string.format('Patched %d level 99 comparisons near JP menu.', patched));
        printMsg('Now reload the addon and test the JP menu.');
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
    elseif cmd == 'request' then
        -- Send packets to request job points data from server
        -- Based on tCrossBar's player.lua:
        -- Packet 0x61 requests main menu data (triggers job point totals via 0x063 subtype 5)
        -- Packet 0xC0 requests job point menu data (triggers categories via 0x08D)
        printMsg('Requesting job points data from server...');

        -- Request main menu data (triggers 0x063 subtype 5)
        local packet1 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        AshitaCore:GetPacketManager():AddOutgoingPacket(0x61, packet1);
        printMsg('  Sent packet 0x61 (main menu request)');

        -- Request job point categories (triggers 0x08D)
        local packet2 = { 0x00, 0x00, 0x00, 0x00 };
        AshitaCore:GetPacketManager():AddOutgoingPacket(0xC0, packet2);
        printMsg('  Sent packet 0xC0 (job point menu request)');

        printMsg('Check chat for packet interception messages.');
    elseif cmd == 'dumpjobs' then
        -- Try to find and dump the job points data structure in memory
        -- The data is structured as: capacityPoints(u16), currentJp(u16), totalJpSpent(u16) per job
        -- Total: 6 bytes per job, 23 jobs (0-22)
        printMsg('Searching for player job levels in memory...');

        -- Try to get player data from Ashita memory manager
        local player = AshitaCore:GetMemoryManager():GetPlayer();
        if player then
            printMsg('Player job levels from Ashita API:');
            for jobId = 1, 22 do
                local level = player:GetJobLevel(jobId);
                local name = jobNames[jobId] or tostring(jobId);
                if level > 0 then
                    printMsg(string.format('  %s (job %d): Level %d', name, jobId, level));
                end
            end

            printMsg('');
            printMsg('Main job: ' .. (jobNames[player:GetMainJob()] or '?') .. ' Lv.' .. player:GetMainJobLevel());
            printMsg('Sub job: ' .. (jobNames[player:GetSubJob()] or '?') .. ' Lv.' .. player:GetSubJobLevel());
        else
            printError('Could not get player object');
        end
    elseif cmd == 'setjobs99' then
        -- Try to set all job levels to 99 in client memory
        -- This is a more direct approach than packet modification
        printMsg('Attempting to set job levels to 99 in client memory...');

        -- The Ashita API is read-only, so we need to find the actual memory location
        -- Look for the pattern of job levels based on what we see from the API
        local player = AshitaCore:GetMemoryManager():GetPlayer();
        if not player then
            printError('Could not get player object');
            return;
        end

        -- Get current job levels to form a search pattern
        local levels = {};
        local patternStr = '';
        for jobId = 1, 10 do
            local level = player:GetJobLevel(jobId);
            table.insert(levels, level);
            patternStr = patternStr .. string.format('%02X', level);
        end

        printMsg('Searching for job level pattern: ' .. patternStr);

        -- Search FFXiMain.dll data sections for this pattern
        local addr = ashita.memory.find('FFXiMain.dll', 0, patternStr, 0, 0);
        if addr ~= 0 then
            printMsg(string.format('Found job levels at 0x%08X', addr));

            -- Read and display current values
            printMsg('Current values:');
            for i = 0, 22 do
                local jobLevel = ashita.memory.read_uint8(addr + i);
                local name = jobNames[i] or tostring(i);
                if jobLevel > 0 then
                    printMsg(string.format('  +%02X: %s = %d', i, name, jobLevel));
                end
            end

            printMsg('');
            printMsg('To set all to 99, run: /ujp forcelvl99 ' .. string.format('%08X', addr));
        else
            printMsg('Could not find job level pattern in FFXiMain.dll');
            printMsg('Try searching with /ujp scanjobmem');
        end
    elseif cmd == 'forcelvl99' then
        -- Force all job levels to 99 at a specific memory address
        if #args < 3 then
            printError('Usage: /ujp forcelvl99 <address>');
            printMsg('Use /ujp setjobs99 first to find the address');
            return;
        end

        local addr = tonumber(args[3], 16);
        if not addr or addr == 0 then
            printError('Invalid address: ' .. args[3]);
            return;
        end

        printMsg(string.format('Setting all job levels to 99 at 0x%08X...', addr));

        -- Save backups and write 99 to each job slot
        for i = 0, 22 do
            local backup = ashita.memory.read_uint8(addr + i);
            if backup > 0 then
                ashita.memory.write_uint8(addr + i, 99);
                printMsg(string.format('  Job %d: %d -> 99', i, backup));
            end
        end

        printSuccess('Job levels set to 99. Check JP menu now!');
        printMsg('Note: This change may be overwritten by incoming packets.');
    elseif cmd == 'scanjobmem' then
        -- Scan for where job levels might be stored
        -- Look for patterns like: multiple consecutive bytes with values in range 1-99
        printMsg('Scanning for potential job level arrays in FFXiMain.dll...');

        -- The player likely has SMN 75, so look for 0x4B at position 15
        -- Combined with other known job levels
        local player = AshitaCore:GetMemoryManager():GetPlayer();
        if not player then
            printError('Could not get player object');
            return;
        end

        -- Build pattern for jobs 12-16 (SAM, NIN, DRG, SMN, BLU)
        -- These are close together in memory
        local pattern = '';
        local patternJobs = '';
        for jobId = 12, 16 do
            local level = player:GetJobLevel(jobId);
            pattern = pattern .. string.format('%02X', level);
            patternJobs = patternJobs .. string.format(' %d=%d', jobId, level);
        end

        printMsg('Searching for pattern:' .. patternJobs);
        printMsg('Pattern hex: ' .. pattern);

        local count = 0;
        local addr = ashita.memory.find('FFXiMain.dll', 0, pattern, 0, count);

        while addr ~= 0 and count < 20 do
            printMsg(string.format('Found at 0x%08X', addr));

            -- Calculate base address (subtract offset for job 12)
            local baseAddr = addr - 12;
            printMsg(string.format('  Potential base: 0x%08X', baseAddr));

            -- Read surrounding context
            printMsg('  Context around match:');
            for i = -4, 20 do
                local byte = ashita.memory.read_uint8(addr + i);
                local marker = '';
                if i == 0 then marker = ' <-- match start'; end
                printMsg(string.format('    +%02d: 0x%02X (%3d)%s', i, byte, byte, marker));
            end

            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, pattern, 0, count);
        end

        if count == 0 then
            printMsg('No matches found.');
        end

        -- Alternative: Try to find the data structure by looking for specific patterns
        -- in the FFXiMain.dll data section
        printMsg('Job Point Entry Structure: {capacityPoints(u16), currentJp(u16), totalJpSpent(u16)}');
        printMsg('SMN is job index 15 (0x0F)');
        printMsg('');
        printMsg('Use /ujp findjpdata to search for JP data pointer');
    elseif cmd == 'findjpdata' then
        -- Try to find the job points data by searching for known patterns
        printMsg('Searching FFXiMain.dll for job points data references...');

        -- Look for code that accesses the job points structure
        -- The client likely has code like: lea reg, [jobPointsArray + jobId*6]
        -- Or: mov reg, [jobPointsArrayPtr]

        -- Search for patterns that reference the totalJpSpent offset (+4)
        local patterns = {
            { pattern = '6683??0600', name = 'cmp word [reg+6],0 (totalJpSpent check)' },
        };

        printMsg('Addresses with totalJpSpent checks:');
        for _, p in ipairs(patterns) do
            local count = 0;
            local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);

            while addr ~= 0 and count < 30 do
                -- Read context around this address to understand the code
                local context = '';
                for i = -4, 12 do
                    context = context .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
                end
                printMsg(string.format('  0x%08X: %s', addr, context));

                count = count + 1;
                addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
            end
        end
    elseif cmd == 'watchmem' then
        -- Watch a memory region for changes (useful for finding what changes when selecting a job)
        if #args < 4 then
            printError('Usage: /ujp watchmem <start_addr> <length>');
            printMsg('Example: /ujp watchmem 04470000 100');
            return;
        end

        local startAddr = tonumber(args[3], 16);
        local length = tonumber(args[4]);

        if not startAddr or not length then
            printError('Invalid address or length');
            return;
        end

        printMsg(string.format('Reading %d bytes from 0x%08X:', length, startAddr));

        local line = '';
        for i = 0, length - 1 do
            local byte = ashita.memory.read_uint8(startAddr + i);
            line = line .. string.format('%02X ', byte);

            if (i + 1) % 16 == 0 then
                printMsg(string.format('  +%03X: %s', i - 15, line));
                line = '';
            end
        end

        if #line > 0 then
            printMsg(string.format('  +%03X: %s', length - (#line / 3), line));
        end
    else
        printError('Unknown command: ' .. cmd);
        printMsg('Use /ujp help for command list.');
    end
end);
