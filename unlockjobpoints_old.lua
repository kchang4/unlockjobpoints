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
    -- Identified patches (addresses may vary by client version):
    [0x045184F7] = 'Job Points Menu Main Check',
    [0x046D84F7] = 'Job Points Menu Main Check (alt)',  -- Same offset, different base
    [0x0459A605] = 'Level Check',
    [0x0475A605] = 'Level Check (alt)',  -- Same offset, different base
    [0x047338F9] = 'Level Check',
    [0x046D9BA6] = 'Per-Job Level Check',  -- THE KEY ONE for enabling individual jobs!
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

-- Test patches table - toggle with /ujp test <number>
-- CONFIRMED: #6 enables main menu, #4 enables job list
local testPatchDefs = {
    { id = 1, addr = 0x0440D77A, byte = 0x7C, orig = 0x75, name = 'JNZ->JL at 0x0440D77A' },
    { id = 2, addr = 0x044DA6D6, byte = 0x7C, orig = 0x75, name = 'JNZ->JL at 0x044DA6D6' },
    { id = 3, addr = 0x047538FA, byte = 0x7C, orig = 0x75, name = 'JNZ->JL at 0x047538FA' },
    { id = 4, addr = 0x045BA605, byte = 0x4B, orig = 0x63, name = 'JOB LIST: cmp al,63h; jb @ 0x045BA604' },
    { id = 5, addr = 0x045BA612, byte = 0x4B, orig = 0x63, name = 'cmp cl,63h; jb' },
    { id = 6, addr = 0x045384F7, byte = 0x4B, orig = 0x63, name = 'MAIN MENU: cmp byte ptr [addr],63h; jnb' },
    { id = 7, addr = 0x044F1DD7, byte = 0x4B, orig = 0x63, name = 'cmp [reg+reg+off],63h; jb' },
    { id = 8, addr = 0x0447E0C0, byte = 0x4B, orig = 0x63, name = 'cmp al,63h; ja' },
    { id = 9, addr = 0x04E0B79D, byte = 0x4B, orig = 0x63, name = 'cmp al,63h; ja' },
    { id = 10, addr = 0x0440D779, byte = 0x4B, orig = 0x63, name = 'cmp al,63h; jl' },
    -- NOP patches: these replace conditional jumps after "cmp word [reg+X], 0" (points spent checks)
    -- byte=0x90 is NOP, we need to NOP 2 bytes (the jump opcode + offset)
    { id = 11, addr = 0x0449402B, byte = 0x90, orig = 0x76, name = 'NOP jbe after cmp word [eax+4],0', byte2 = 0x90, orig2 = 0x07 },
    { id = 12, addr = 0x0454064A, byte = 0x90, orig = 0x74, name = 'NOP je after cmp word [eax+4],0', byte2 = 0x90, orig2 = 0x0B },
    { id = 13, addr = 0x044940B7, byte = 0x90, orig = 0x76, name = 'NOP jbe after cmp word [esi+4],0', byte2 = 0x90, orig2 = 0x08 },
    { id = 14, addr = 0x0449410D, byte = 0x90, orig = 0x76, name = 'NOP jbe after cmp word [esi+4],0', byte2 = 0x90, orig2 = 0x08 },
    { id = 15, addr = 0x044E18E5, byte = 0x90, orig = 0x76, name = 'NOP jbe after cmp word [ecx+4],0', byte2 = 0x90, orig2 = 0x0B },
    { id = 16, addr = 0x04E447FD, byte = 0x90, orig = 0x76, name = 'NOP jbe after cmp word [ecx+4],0', byte2 = 0x90, orig2 = 0x0B },
    { id = 17, addr = 0x044C8EE2, byte = 0x90, orig = 0x76, name = 'NOP jbe after cmp word [esi+6],0', byte2 = 0x90, orig2 = 0x06 },
    { id = 18, addr = 0x045CF549, byte = 0x90, orig = 0x74, name = 'NOP je after cmp word [ecx+6],0', byte2 = 0x90, orig2 = 0x21 },
    { id = 19, addr = 0x04ED0B69, byte = 0x90, orig = 0x74, name = 'NOP je after cmp word [ecx+6],0', byte2 = 0x90, orig2 = 0x21 },
    { id = 20, addr = 0x044D37C2, byte = 0x90, orig = 0x74, name = 'NOP je after cmp word [ebp+6],0', byte2 = 0x90, orig2 = 0x4E },
    { id = 21, addr = 0x044D9467, byte = 0x90, orig = 0x74, name = 'NOP je after cmp word [edx+6],0', byte2 = 0x90, orig2 = 0x09 },
    { id = 22, addr = 0x04E3FFE0, byte = 0x90, orig = 0x74, name = 'NOP je after cmp word [edx+6],0', byte2 = 0x90, orig2 = 0xDF },
};

-- Track which test patches are currently enabled
local testPatchState = {};

local function applyTestPatch(id)
    for _, p in ipairs(testPatchDefs) do
        if p.id == id then
            local current = ashita.memory.read_uint8(p.addr);
            if current == p.orig then
                ashita.memory.write_uint8(p.addr, p.byte);
                -- Handle 2-byte NOP patches
                if p.byte2 then
                    ashita.memory.write_uint8(p.addr + 1, p.byte2);
                end
                testPatchState[id] = true;
                printSuccess(string.format('Enabled patch #%d: %s', id, p.name));
                return true;
            else
                printMsg(string.format('Patch #%d already applied or different (current: 0x%02X)', id, current));
                return false;
            end
        end
    end
    printError(string.format('Patch #%d not found', id));
    return false;
end

local function removeTestPatch(id)
    for _, p in ipairs(testPatchDefs) do
        if p.id == id then
            local current = ashita.memory.read_uint8(p.addr);
            if current == p.byte then
                ashita.memory.write_uint8(p.addr, p.orig);
                -- Handle 2-byte NOP patches
                if p.orig2 then
                    ashita.memory.write_uint8(p.addr + 1, p.orig2);
                end
                testPatchState[id] = false;
                printSuccess(string.format('Disabled patch #%d: %s', id, p.name));
                return true;
            else
                printMsg(string.format('Patch #%d not currently applied (current: 0x%02X)', id, current));
                return false;
            end
        end
    end
    printError(string.format('Patch #%d not found', id));
    return false;
end

local function listTestPatches()
    printMsg('=== Test Patches ===');
    for _, p in ipairs(testPatchDefs) do
        local current = ashita.memory.read_uint8(p.addr);
        local status = (current == p.byte) and '[ON]' or '[OFF]';
        printMsg(string.format('%s #%d: %s', status, p.id, p.name));
    end
    printMsg('Commands: /ujp on <num>, /ujp off <num>, /ujp list, /ujp scan');
end

-- Dump bytes around the two confirmed patches to help build better patterns
local function dumpPatternContext()
    printMsg('=== Dumping context for confirmed patches (40 bytes before/after) ===');
    
    -- Main menu patch - find it dynamically
    local mainMenuPattern = 'F6000174??803D??????????73';
    local mainAddr = ashita.memory.find('FFXiMain.dll', 0, mainMenuPattern, 0, 0);
    if mainAddr ~= 0 then
        mainAddr = mainAddr + 11;  -- offset to level byte
    else
        mainAddr = 0x045384F7;  -- fallback to known address
    end
    
    printMsg(string.format('MAIN MENU @ 0x%08X:', mainAddr));
    printMsg('Bytes -40 to -21:');
    local ctx = '';
    for i = -40, -21 do
        ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(mainAddr + i));
    end
    printMsg(ctx);
    printMsg('Bytes -20 to -1:');
    ctx = '';
    for i = -20, -1 do
        ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(mainAddr + i));
    end
    printMsg(ctx);
    printMsg('Bytes 0 to +19 (level byte at 0):');
    ctx = '';
    for i = 0, 19 do
        if i == 0 then ctx = ctx .. '['; end
        ctx = ctx .. string.format('%02X', ashita.memory.read_uint8(mainAddr + i));
        if i == 0 then ctx = ctx .. ']'; end
        ctx = ctx .. ' ';
    end
    printMsg(ctx);
    printMsg('Bytes +20 to +40:');
    ctx = '';
    for i = 20, 40 do
        ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(mainAddr + i));
    end
    printMsg(ctx);
    
    -- Job list patch - find it dynamically
    local jobListPattern = '80F92974??80F92B74??3C??72';
    local jobAddr = ashita.memory.find('FFXiMain.dll', 0, jobListPattern, 0, 0);
    if jobAddr ~= 0 then
        jobAddr = jobAddr + 11;  -- offset to level byte
    else
        jobAddr = 0x045BA605;  -- fallback to known address
    end
    
    printMsg('');
    printMsg(string.format('JOB LIST @ 0x%08X:', jobAddr));
    printMsg('Bytes -40 to -21:');
    ctx = '';
    for i = -40, -21 do
        ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(jobAddr + i));
    end
    printMsg(ctx);
    printMsg('Bytes -20 to -1:');
    ctx = '';
    for i = -20, -1 do
        ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(jobAddr + i));
    end
    printMsg(ctx);
    printMsg('Bytes 0 to +19 (level byte at 0):');
    ctx = '';
    for i = 0, 19 do
        if i == 0 then ctx = ctx .. '['; end
        ctx = ctx .. string.format('%02X', ashita.memory.read_uint8(jobAddr + i));
        if i == 0 then ctx = ctx .. ']'; end
        ctx = ctx .. ' ';
    end
    printMsg(ctx);
    printMsg('Bytes +20 to +40:');
    ctx = '';
    for i = 20, 40 do
        ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(jobAddr + i));
    end
    printMsg(ctx);
    
    printMsg('');
    printMsg('Use these byte sequences to build unique patterns.');
    printMsg('Replace variable bytes with ?? for wildcards.');
end

-- Dynamic scan results storage
local scanResults = {};

local function scanForPatternsv2()
    scanResults = {};
    printMsg('=== Scanning FFXiMain.dll for level 99 comparisons... ===');
    
    -- Patterns to search for (without jump byte - we'll check that separately)
    local searchPatterns = {
        -- cmp byte ptr [reg+off], 63h
        { search = '807E??63', offset = 3, name = 'cmp [esi+off],63h' },
        { search = '807F??63', offset = 3, name = 'cmp [edi+off],63h' },
        { search = '8078??63', offset = 3, name = 'cmp [eax+off],63h' },
        { search = '8079??63', offset = 3, name = 'cmp [ecx+off],63h' },
        { search = '807A??63', offset = 3, name = 'cmp [edx+off],63h' },
        { search = '807B??63', offset = 3, name = 'cmp [ebx+off],63h' },
        { search = '807D??63', offset = 3, name = 'cmp [ebp+off],63h' },
        -- cmp al, 63h
        { search = '3C63', offset = 1, name = 'cmp al,63h' },
        -- cmp cl/dl/bl, 63h
        { search = '80F963', offset = 2, name = 'cmp cl,63h' },
        { search = '80FA63', offset = 2, name = 'cmp dl,63h' },
        { search = '80FB63', offset = 2, name = 'cmp bl,63h' },
        -- cmp eax/ecx/edx, 63h
        { search = '83F863', offset = 2, name = 'cmp eax,63h' },
        { search = '83F963', offset = 2, name = 'cmp ecx,63h' },
        { search = '83FA63', offset = 2, name = 'cmp edx,63h' },
        { search = '83FB63', offset = 2, name = 'cmp ebx,63h' },
        { search = '83FE63', offset = 2, name = 'cmp esi,63h' },
        { search = '83FF63', offset = 2, name = 'cmp edi,63h' },
        -- cmp byte ptr [static addr], 63h
        { search = '803D????????63', offset = 6, name = 'cmp byte ptr [addr],63h' },
        -- Array index: cmp byte ptr [reg+reg*scale+off], 63h
        { search = '803C??63', offset = 3, name = 'cmp [reg+reg],63h' },
        { search = '807C????63', offset = 4, name = 'cmp [reg+reg+off],63h' },
    };
    
    local resultId = 1;
    for _, pat in ipairs(searchPatterns) do
        local count = 0;
        local addr = ashita.memory.find('FFXiMain.dll', 0, pat.search, 0, 0);
        while addr ~= 0 and count < 50 do
            -- Read the byte after the 63 to see if it's a jump
            local jmpOff = pat.offset + 1;
            local jmpByte = ashita.memory.read_uint8(addr + jmpOff);
            local jmpName = '';
            local isJump = true;
            if jmpByte == 0x72 then jmpName = 'jb';
            elseif jmpByte == 0x73 then jmpName = 'jnb';
            elseif jmpByte == 0x74 then jmpName = 'je';
            elseif jmpByte == 0x75 then jmpName = 'jne';
            elseif jmpByte == 0x76 then jmpName = 'jbe';
            elseif jmpByte == 0x77 then jmpName = 'ja';
            elseif jmpByte == 0x7C then jmpName = 'jl';
            elseif jmpByte == 0x7D then jmpName = 'jge';
            elseif jmpByte == 0x7E then jmpName = 'jle';
            elseif jmpByte == 0x7F then jmpName = 'jg';
            elseif jmpByte == 0x0F then jmpName = 'jcc32';  -- 32-bit conditional jump
            else 
                jmpName = string.format('0x%02X', jmpByte);
                isJump = false;
            end
            
            -- Only include if followed by a jump instruction
            if isJump then
                table.insert(scanResults, {
                    id = resultId,
                    addr = addr + pat.offset,
                    jmpAddr = addr + jmpOff,
                    jmpByte = jmpByte,
                    name = string.format('%s; %s @ 0x%08X', pat.name, jmpName, addr),
                });
                resultId = resultId + 1;
            end
            
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, pat.search, 0, count);
        end
    end
    
    printSuccess(string.format('Found %d matches', #scanResults));
    for i, r in ipairs(scanResults) do
        printMsg(string.format('#%d: %s', r.id, r.name));
    end
    printMsg('Use /ujp patchscan <num> to change 63h->4Bh');
    printMsg('Use /ujp jmpscan <num> to change Jcc->JMP (like nomad addon)');
end

-- Search for ARRAY-INDEXED level checks (for per-job list)
-- These use registers for indexing: cmp byte ptr [base + reg], 63h
local function searchArrayPatterns()
    scanResults = {};
    printMsg('=== Searching for ARRAY-INDEXED level 99 checks ===');
    printMsg('(These loop through all jobs checking each level)');
    
    local results = {};
    local resultId = 1;
    
    -- Array-indexed patterns use SIB byte addressing
    -- Format: 80 7C [SIB] [disp8] 63 or 80 3C [SIB] 63
    local arrayPatterns = {
        -- cmp byte ptr [reg + reg*1 + disp8], 63h (with conditional jump)
        { search = '807C??006372', offset = 4, jmpOff = 5, name = 'cmp [r+r+0],63; jb' },
        { search = '807C??006373', offset = 4, jmpOff = 5, name = 'cmp [r+r+0],63; jnb' },
        { search = '807C??006374', offset = 4, jmpOff = 5, name = 'cmp [r+r+0],63; je' },
        { search = '807C??006375', offset = 4, jmpOff = 5, name = 'cmp [r+r+0],63; jne' },
        { search = '807C????6372', offset = 4, jmpOff = 5, name = 'cmp [r+r+d],63; jb' },
        { search = '807C????6373', offset = 4, jmpOff = 5, name = 'cmp [r+r+d],63; jnb' },
        { search = '807C????6374', offset = 4, jmpOff = 5, name = 'cmp [r+r+d],63; je' },
        { search = '807C????6375', offset = 4, jmpOff = 5, name = 'cmp [r+r+d],63; jne' },
        -- cmp byte ptr [reg + reg], 63h (no displacement)
        { search = '803C??6372', offset = 3, jmpOff = 4, name = 'cmp [r+r],63; jb' },
        { search = '803C??6373', offset = 3, jmpOff = 4, name = 'cmp [r+r],63; jnb' },
        { search = '803C??6374', offset = 3, jmpOff = 4, name = 'cmp [r+r],63; je' },
        { search = '803C??6375', offset = 3, jmpOff = 4, name = 'cmp [r+r],63; jne' },
        -- movzx then cmp al, 63 pattern (common for array access)
        { search = '0FB604??3C6372', offset = 5, jmpOff = 6, name = 'movzx eax,[r+r]; cmp al,63; jb' },
        { search = '0FB604??3C6373', offset = 5, jmpOff = 6, name = 'movzx eax,[r+r]; cmp al,63; jnb' },
        { search = '0FB60C??3C6372', offset = 5, jmpOff = 6, name = 'movzx ecx,[r+r]; cmp al,63; jb' },
        { search = '0FB60C??3C6373', offset = 5, jmpOff = 6, name = 'movzx ecx,[r+r]; cmp al,63; jnb' },
        -- More general: any movzx followed by cmp with 63
        { search = '0FB6??3C6372', offset = 4, jmpOff = 5, name = 'movzx r8,[m]; cmp al,63; jb' },
        { search = '0FB6??3C6373', offset = 4, jmpOff = 5, name = 'movzx r8,[m]; cmp al,63; jnb' },
        { search = '0FB6??3C6374', offset = 4, jmpOff = 5, name = 'movzx r8,[m]; cmp al,63; je' },
        { search = '0FB6??3C6375', offset = 4, jmpOff = 5, name = 'movzx r8,[m]; cmp al,63; jne' },
        -- cmp with memory operand using 32-bit displacement
        { search = '807C????????6372', offset = 6, jmpOff = 7, name = 'cmp [r+r+d32],63; jb' },
        { search = '807C????????6373', offset = 6, jmpOff = 7, name = 'cmp [r+r+d32],63; jnb' },
        -- Less common but possible: cmp reg, [array+index] then cmp with imm
        { search = '3A??3C6372', offset = 3, jmpOff = 4, name = 'cmp r,[m]; cmp al,63; jb' },
        { search = '3A??3C6373', offset = 3, jmpOff = 4, name = 'cmp r,[m]; cmp al,63; jnb' },
    };
    
    for _, pat in ipairs(arrayPatterns) do
        local addr = ashita.memory.find('FFXiMain.dll', 0, pat.search, 0, 0);
        local count = 0;
        while addr ~= 0 and count < 15 do
            local ctx = '';
            for i = -2, 12 do
                ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
            end
            
            local jmpByte = ashita.memory.read_uint8(addr + pat.jmpOff);
            table.insert(scanResults, {
                id = resultId,
                addr = addr + pat.offset,
                jmpAddr = addr + pat.jmpOff,
                jmpByte = jmpByte,
                name = string.format('%s @ 0x%08X', pat.name, addr),
                context = ctx,
            });
            resultId = resultId + 1;
            
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, pat.search, 0, count);
        end
    end
    
    printSuccess(string.format('Found %d array-indexed patterns', #scanResults));
    for _, r in ipairs(scanResults) do
        printMsg(string.format('#%d: %s', r.id, r.name));
        printMsg(string.format('    %s', r.context));
    end
    printMsg('Use /ujp patchscan <num> or /ujp patchrange 1 %d', #scanResults);
end

-- Analyze the working main menu patch and search for similar code nearby
local function analyzeMainMenu()
    local mainMenuAddr = 0x045384F7;  -- The confirmed working patch address
    
    printMsg('=== Analyzing Main Menu Patch ===');
    printMsg(string.format('Main menu patch at 0x%08X', mainMenuAddr));
    
    -- Read bytes around the patch to understand the full instruction sequence
    printMsg('Bytes around main menu patch:');
    local context = '';
    for i = -16, 16 do
        if i == 0 then context = context .. '['; end
        context = context .. string.format('%02X', ashita.memory.read_uint8(mainMenuAddr + i));
        if i == 0 then context = context .. ']'; end
        context = context .. ' ';
    end
    printMsg(context);
    
    -- The main menu pattern uses: 803D ???????? 63 73 (cmp byte ptr [addr], 63h; jnb)
    -- Let's find the static address it's comparing
    local staticAddr = ashita.memory.read_uint32(mainMenuAddr - 4);  -- Read the address operand
    printMsg(string.format('Static address being compared: 0x%08X', staticAddr));
    
    -- Read what's at that static address
    local valueAtStatic = ashita.memory.read_uint8(staticAddr);
    printMsg(string.format('Value at static address: %d (0x%02X) - this is your main job level', valueAtStatic, valueAtStatic));
    
    -- Now search for OTHER code that references this same static address
    -- Pattern: any instruction that uses this address
    local addrBytes = string.format('%02X%02X%02X%02X', 
        bit.band(staticAddr, 0xFF),
        bit.band(bit.rshift(staticAddr, 8), 0xFF),
        bit.band(bit.rshift(staticAddr, 16), 0xFF),
        bit.band(bit.rshift(staticAddr, 24), 0xFF));
    
    printMsg(string.format('Searching for references to 0x%08X (pattern: %s)...', staticAddr, addrBytes));
    
    local count = 0;
    local addr = ashita.memory.find('FFXiMain.dll', 0, addrBytes, 0, 0);
    while addr ~= 0 and count < 30 do
        -- Read context around this reference
        local ctx = '';
        for i = -4, 8 do
            ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
        end
        printMsg(string.format('  0x%08X: %s', addr, ctx));
        count = count + 1;
        addr = ashita.memory.find('FFXiMain.dll', 0, addrBytes, 0, count);
    end
    printMsg(string.format('Found %d references to the static address', count));
    
    -- Also check if there's a job levels ARRAY nearby
    -- The per-job check would access jobLevels[jobIndex] instead of a fixed address
    printMsg('');
    printMsg('Looking for job level array patterns near main menu code...');
    
    -- Search for array-indexed level checks near the main menu function
    -- Pattern: 807C???? 63 (cmp byte ptr [reg+reg*scale+off], 63h)
    local nearStart = mainMenuAddr - 0x1000;
    local nearEnd = mainMenuAddr + 0x1000;
    
    local arrayPatterns = {
        { pat = '3A??63', name = 'cmp reg,[mem] with 63h' },
        { pat = '807C', name = 'cmp byte ptr [SIB]' },
        { pat = '0FB6', name = 'movzx (often before cmp)' },
    };
    
    local nearCount = 0;
    for _, p in ipairs(arrayPatterns) do
        local a = ashita.memory.find('FFXiMain.dll', 0, p.pat, 0, 0);
        local c = 0;
        while a ~= 0 and c < 100 do
            if a >= nearStart and a <= nearEnd then
                local ctx = '';
                for i = 0, 10 do
                    ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(a + i));
                end
                printMsg(string.format('  %s at 0x%08X: %s', p.name, a, ctx));
                nearCount = nearCount + 1;
            end
            c = c + 1;
            a = ashita.memory.find('FFXiMain.dll', 0, p.pat, 0, c);
        end
    end
    printMsg(string.format('Found %d array-like patterns near main menu', nearCount));
end

-- Search for patterns containing both job ID and level 99 check
local function searchJobPattern(jobId)
    local jobName = jobNames[jobId] or tostring(jobId);
    printMsg(string.format('=== Searching for %s (job %d / 0x%02X) + level 99 patterns ===', jobName, jobId, jobId));
    
    -- The per-job check likely does something like:
    -- cmp byte ptr [baseAddr + jobId], 63h  or
    -- push jobId; ... cmp al, 63h  or
    -- mov reg, jobId; ... cmp [reg+offset], 63h
    
    local results = {};
    local resultId = 1;
    
    -- Pattern 1: Job ID followed by 63 within a few bytes
    -- e.g., 0F ... 63 (job 15 SMN followed by level 99)
    for distance = 1, 8 do
        local pattern = string.format('%02X', jobId);
        for i = 1, distance do
            pattern = pattern .. '??';
        end
        pattern = pattern .. '63';
        
        local addr = ashita.memory.find('FFXiMain.dll', 0, pattern, 0, 0);
        local count = 0;
        while addr ~= 0 and count < 20 do
            -- Read full context
            local ctx = '';
            for i = -4, 12 do
                ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
            end
            
            -- Check if this looks like code (not data)
            local prevByte = ashita.memory.read_uint8(addr - 1);
            local isLikelyCode = (prevByte >= 0x80 and prevByte <= 0x8F) or  -- cmp/mov opcodes
                                 (prevByte >= 0x38 and prevByte <= 0x3F) or  -- cmp opcodes
                                 (prevByte >= 0x00 and prevByte <= 0x07) or  -- add opcodes
                                 (prevByte == 0x6A) or  -- push imm8
                                 (prevByte == 0xB0) or (prevByte == 0xB1) or  -- mov al/cl, imm8
                                 (prevByte >= 0x88 and prevByte <= 0x8B);     -- mov opcodes
            
            if isLikelyCode then
                table.insert(results, {
                    id = resultId,
                    addr = addr,
                    lvlAddr = addr + distance + 1,
                    pattern = string.format('job%02X+%d+63', jobId, distance),
                    context = ctx,
                });
                resultId = resultId + 1;
            end
            
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, pattern, 0, count);
        end
    end
    
    -- Pattern 2: 63 followed by job ID within a few bytes
    for distance = 1, 8 do
        local pattern = '63';
        for i = 1, distance do
            pattern = pattern .. '??';
        end
        pattern = pattern .. string.format('%02X', jobId);
        
        local addr = ashita.memory.find('FFXiMain.dll', 0, pattern, 0, 0);
        local count = 0;
        while addr ~= 0 and count < 20 do
            local ctx = '';
            for i = -4, 12 do
                ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
            end
            
            local prevByte = ashita.memory.read_uint8(addr - 1);
            local isLikelyCode = (prevByte >= 0x80 and prevByte <= 0x8F) or
                                 (prevByte >= 0x38 and prevByte <= 0x3F) or
                                 (prevByte == 0x3C) or  -- cmp al, imm
                                 (prevByte >= 0xF8 and prevByte <= 0xFF);  -- cmp reg, imm
            
            if isLikelyCode then
                table.insert(results, {
                    id = resultId,
                    addr = addr,
                    lvlAddr = addr,
                    pattern = string.format('63+%d+job%02X', distance, jobId),
                    context = ctx,
                });
                resultId = resultId + 1;
            end
            
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, pattern, 0, count);
        end
    end
    
    -- Pattern 3: cmp with job offset in SIB byte
    -- cmp byte ptr [reg + jobId], 63h = 80 7? 0F 63 (for job 15)
    local sibPatterns = {
        string.format('8078%02X63', jobId),  -- cmp byte ptr [eax+jobId], 63h
        string.format('8079%02X63', jobId),  -- cmp byte ptr [ecx+jobId], 63h
        string.format('807A%02X63', jobId),  -- cmp byte ptr [edx+jobId], 63h
        string.format('807B%02X63', jobId),  -- cmp byte ptr [ebx+jobId], 63h
        string.format('807E%02X63', jobId),  -- cmp byte ptr [esi+jobId], 63h
        string.format('807F%02X63', jobId),  -- cmp byte ptr [edi+jobId], 63h
    };
    
    for _, pat in ipairs(sibPatterns) do
        local addr = ashita.memory.find('FFXiMain.dll', 0, pat, 0, 0);
        local count = 0;
        while addr ~= 0 and count < 10 do
            local ctx = '';
            for i = -2, 10 do
                ctx = ctx .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
            end
            table.insert(results, {
                id = resultId,
                addr = addr,
                lvlAddr = addr + 3,
                pattern = pat,
                context = ctx,
            });
            resultId = resultId + 1;
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, pat, 0, count);
        end
    end
    
    -- Store results for patching
    scanResults = {};
    for _, r in ipairs(results) do
        table.insert(scanResults, {
            id = r.id,
            addr = r.lvlAddr,
            jmpAddr = r.lvlAddr + 1,
            jmpByte = ashita.memory.read_uint8(r.lvlAddr + 1),
            name = string.format('%s @ 0x%08X', r.pattern, r.addr),
        });
    end
    
    printSuccess(string.format('Found %d patterns for %s', #results, jobName));
    for _, r in ipairs(results) do
        printMsg(string.format('#%d: %s - %s', r.id, r.pattern, r.context));
    end
    printMsg('Use /ujp patchscan <num> to patch 63->4B');
    printMsg('Use /ujp patchrange <start> <end> to patch a range');
end

-- Patch a range of scan results
local function patchScanRange(startId, endId)
    local patched = 0;
    for _, r in ipairs(scanResults) do
        if r.id >= startId and r.id <= endId then
            local current = ashita.memory.read_uint8(r.addr);
            if current == 0x63 then
                ashita.memory.write_uint8(r.addr, 0x4B);
                printMsg(string.format('Patched #%d at 0x%08X', r.id, r.addr));
                patched = patched + 1;
            end
        end
    end
    printSuccess(string.format('Patched %d results in range %d-%d', patched, startId, endId));
    return patched;
end

-- Restore scan results to original (for testing)
local function restoreScanRange(startId, endId)
    local restored = 0;
    for _, r in ipairs(scanResults) do
        if r.id >= startId and r.id <= endId then
            local current = ashita.memory.read_uint8(r.addr);
            if current == 0x4B then
                ashita.memory.write_uint8(r.addr, 0x63);
                printMsg(string.format('Restored #%d at 0x%08X', r.id, r.addr));
                restored = restored + 1;
            end
        end
    end
    printSuccess(string.format('Restored %d results in range %d-%d', restored, startId, endId));
    return restored;
end

-- Show which scan results are currently patched
local function showPatchedStatus()
    if #scanResults == 0 then
        printError('No scan results. Run /ujp scan2 first');
        return;
    end
    local patched = {};
    local unpatched = {};
    for _, r in ipairs(scanResults) do
        local current = ashita.memory.read_uint8(r.addr);
        if current == 0x4B then
            table.insert(patched, r.id);
        else
            table.insert(unpatched, r.id);
        end
    end
    printMsg(string.format('Total: %d scan results', #scanResults));
    if #patched > 0 then
        printSuccess(string.format('Patched (%d): %s', #patched, table.concat(patched, ', ')));
    else
        printMsg('Patched: none');
    end
end

local function patchScanResult(id)
    for _, r in ipairs(scanResults) do
        if r.id == id then
            local current = ashita.memory.read_uint8(r.addr);
            if current == 0x63 then
                ashita.memory.write_uint8(r.addr, 0x4B);
                printSuccess(string.format('Patched #%d: 63h->4Bh at 0x%08X', id, r.addr));
                return true;
            else
                printError(string.format('#%d already patched or different (0x%02X)', id, current));
                return false;
            end
        end
    end
    printError(string.format('Scan result #%d not found. Run /ujp scan first', id));
    return false;
end

local function nopScanResult(id)
    for _, r in ipairs(scanResults) do
        if r.id == id then
            local current = ashita.memory.read_uint8(r.jmpAddr);
            if current == r.jmpByte then
                ashita.memory.write_uint8(r.jmpAddr, 0x90);
                ashita.memory.write_uint8(r.jmpAddr + 1, 0x90);
                printSuccess(string.format('NOPed #%d: jump at 0x%08X', id, r.jmpAddr));
                return true;
            else
                printError(string.format('#%d jump already NOPed or different (0x%02X)', id, current));
                return false;
            end
        end
    end
    printError(string.format('Scan result #%d not found. Run /ujp scan2 first', id));
    return false;
end

-- Like nomad addon: change conditional jump to unconditional JMP (0xEB)
local function jmpScanResult(id)
    for _, r in ipairs(scanResults) do
        if r.id == id then
            local current = ashita.memory.read_uint8(r.jmpAddr);
            if current == r.jmpByte then
                -- Change Jcc to JMP short (0xEB)
                ashita.memory.write_uint8(r.jmpAddr, 0xEB);
                printSuccess(string.format('JMP #%d: 0x%02X->0xEB at 0x%08X (unconditional jump)', id, r.jmpByte, r.jmpAddr));
                return true;
            elseif current == 0xEB then
                printError(string.format('#%d already patched to JMP', id));
                return false;
            else
                printError(string.format('#%d jump different (0x%02X, expected 0x%02X)', id, current, r.jmpByte));
                return false;
            end
        end
    end
    printError(string.format('Scan result #%d not found. Run /ujp scan2 first', id));
    return false;
end

local function searchAndPatch()
    local patchCount = 0;

    -- MAIN MENU pattern (48 chars = 24 bytes, like nomad):
    -- Full context: 85 C0 74 0E F6 00 01 74 09 80 3D [4-byte addr] [63] 73 0C 8B 4E 08 6A 08 6A 05
    -- Actual memory: 85 C0 74 0E F6 00 01 74 09 80 3D D1 33 87 04 63 73 0C 8B 4E 08 6A 08 6A 05
    -- Unique anchors: 85C0740E (test eax,eax; jz +0E) + F60001 (test [eax],01) + 8B4E086A086A05 (mov ecx,[esi+8]; push 8; push 5)
    -- Pattern bytes: 85 C0 74 0E F6 00 01 74 ?? 80 3D ?? ?? ?? ?? ?? 73 ?? 8B 4E 08 6A 08 6A 05
    -- Positions:      0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24
    -- The level byte (63) is at position 15 - use wildcard so it matches both 63 and 4B
    local mainMenuPattern = '85C0740EF6000174??803D??????????73??8B4E086A086A05';
    local mainMenuAddr = ashita.memory.find('FFXiMain.dll', 0, mainMenuPattern, 0, 0);
    if mainMenuAddr ~= 0 then
        local patchAddr = mainMenuAddr + 15;  -- offset to the level byte
        local current = ashita.memory.read_uint8(patchAddr);
        if current == 0x63 then
            ashita.memory.write_uint8(patchAddr, 0x4B);
            table.insert(state.patches, { ptr = patchAddr, backup = 0x63, pattern = 'main_menu' });
            printSuccess(string.format('MAIN MENU: Patched 0x%08X (63->4B)', patchAddr));
            patchCount = patchCount + 1;
        elseif current == 0x4B then
            -- Already patched, still count as success but stay silent
            table.insert(state.patches, { ptr = patchAddr, backup = 0x63, pattern = 'main_menu' });
            patchCount = patchCount + 1;
        else
            printError(string.format('MAIN MENU: Unexpected byte 0x%02X at 0x%08X', current, patchAddr));
        end
    else
        printError('MAIN MENU: Pattern not found');
    end
    
    -- JOB LIST pattern (54 chars = 27 bytes, like nomad):
    -- Full context: 8A 8E FF 01 00 00 80 F9 29 74 ?? 80 F9 2B 74 ?? 3C [63] 72 ?? 77 ?? 8A 8E FF 01 00 00
    -- Unique anchors: 8A8EFF010000 (mov cl,[esi+1FFh]) appears TWICE - extremely unique!
    -- The level byte (63) is at offset 17 from pattern start
    local jobListPattern = '8A8EFF01000080F92974??80F92B74??3C??72??77??8A8EFF010000';
    local jobListAddr = ashita.memory.find('FFXiMain.dll', 0, jobListPattern, 0, 0);
    if jobListAddr ~= 0 then
        local patchAddr = jobListAddr + 17;  -- offset to the level byte
        local current = ashita.memory.read_uint8(patchAddr);
        if current == 0x63 then
            ashita.memory.write_uint8(patchAddr, 0x4B);
            table.insert(state.patches, { ptr = patchAddr, backup = 0x63, pattern = 'job_list' });
            printSuccess(string.format('JOB LIST: Patched 0x%08X (63->4B)', patchAddr));
            patchCount = patchCount + 1;
        elseif current == 0x4B then
            -- Already patched, still count as success but stay silent
            table.insert(state.patches, { ptr = patchAddr, backup = 0x63, pattern = 'job_list' });
            patchCount = patchCount + 1;
        else
            printError(string.format('JOB LIST: Unexpected byte 0x%02X at 0x%08X', current, patchAddr));
        end
    else
        printError('JOB LIST: Pattern not found');
    end
    
    return patchCount;
end

--[[ DISABLED: Full pattern matching for testing
local function searchAndPatch_DISABLED()
    local patchCount = 0;
    local patched = {};
    -- RE-ENABLED: JNZ->JL patches for proper >= comparison
                patched[patchAddr] = true;
                patchCount = patchCount + 1;
            end
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, critical.search, 0, count);
        end
    end

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

    -- Continue with pattern-based patching (patched table already exists from above)
    -- Log all patches to help identify which one enables the main menu
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
                    -- Log the patch with address for debugging
                    printMsg(string.format('PATCH #%d: 0x%08X - %s', patchCount + 1, patchAddr, p.name));
                    applyPatch(patchAddr, TARGET_LEVEL, p.name);
                    patched[patchAddr] = true;
                    patchCount = patchCount + 1;
                    
                    -- Also check if there's a JNE (0x75) after the level byte that needs JL (0x7C)
                    local jumpAddr = patchAddr + 1;
                    local jumpByte = ashita.memory.read_uint8(jumpAddr);
                    if jumpByte == 0x75 and not patched[jumpAddr] then -- JNE
                        printMsg(string.format('PATCH #%d: 0x%08X - %s', patchCount + 1, jumpAddr, p.name .. ' JNE->JL'));
                        applyPatch(jumpAddr, 0x7C, p.name .. ' JNE->JL');
                        patched[jumpAddr] = true;
                        patchCount = patchCount + 1;
                    end
                end
            end

            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
        end
    end

    return patchCount;
end
--]] -- End of DISABLED searchAndPatch_DISABLED

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

    -- Search for generic cmp word patterns - MORE AGGRESSIVE
    -- Pattern: 66 83 7? XX 00 (cmp word [reg+XX], 0) where reg is any register
    local patterns = {
        -- Offset +4 patterns (all registers)
        { pattern = '6683780400', name = 'cmp word [eax+4],0' },
        { pattern = '6683790400', name = 'cmp word [ecx+4],0' },
        { pattern = '66837A0400', name = 'cmp word [edx+4],0' },
        { pattern = '66837B0400', name = 'cmp word [ebx+4],0' },
        { pattern = '66837D0400', name = 'cmp word [ebp+4],0' },
        { pattern = '66837E0400', name = 'cmp word [esi+4],0' },
        { pattern = '66837F0400', name = 'cmp word [edi+4],0' },
        -- Offset +6 patterns (all registers)
        { pattern = '6683780600', name = 'cmp word [eax+6],0' },
        { pattern = '6683790600', name = 'cmp word [ecx+6],0' },
        { pattern = '66837A0600', name = 'cmp word [edx+6],0' },
        { pattern = '66837B0600', name = 'cmp word [ebx+6],0' },
        { pattern = '66837D0600', name = 'cmp word [ebp+6],0' },
        { pattern = '66837E0600', name = 'cmp word [esi+6],0' },
        { pattern = '66837F0600', name = 'cmp word [edi+6],0' },
        -- Offset +0 patterns (checking base struct)
        { pattern = '6683780000', name = 'cmp word [eax+0],0' },
        { pattern = '6683790000', name = 'cmp word [ecx+0],0' },
        { pattern = '66837E0000', name = 'cmp word [esi+0],0' },
        { pattern = '66837F0000', name = 'cmp word [edi+0],0' },
        -- Offset +2 patterns  
        { pattern = '6683780200', name = 'cmp word [eax+2],0' },
        { pattern = '6683790200', name = 'cmp word [ecx+2],0' },
        { pattern = '66837E0200', name = 'cmp word [esi+2],0' },
        { pattern = '66837F0200', name = 'cmp word [edi+2],0' },
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
* Returns table of results for potential patching
--]]
local function scanAll99(doPatch)
    printMsg('Scanning FFXiMain.dll for ALL level 99 (0x63) comparisons...');
    if doPatch then
        printMsg('Will patch all found patterns to 0x4B (75)...');
    else
        printMsg('This may find many false positives. Use /ujp patchscanall to patch them.');
    end

    -- Very broad patterns - just looking for 0x63 in comparison contexts
    local patterns = {
        -- Any cmp byte with 0x63
        { pattern = '3C63',   offset = 1, name = 'cmp al,63h' },
        { pattern = '80F863', offset = 2, name = 'cmp al,63h (alt)' },
        { pattern = '80F963', offset = 2, name = 'cmp cl,63h' },
        { pattern = '80FA63', offset = 2, name = 'cmp dl,63h' },
        { pattern = '80FB63', offset = 2, name = 'cmp bl,63h' },
        { pattern = '83F863', offset = 2, name = 'cmp eax,63h' },
        { pattern = '83F963', offset = 2, name = 'cmp ecx,63h' },
        { pattern = '83FA63', offset = 2, name = 'cmp edx,63h' },
        { pattern = '83FB63', offset = 2, name = 'cmp ebx,63h' },
        { pattern = '83FE63', offset = 2, name = 'cmp esi,63h' },
        { pattern = '83FF63', offset = 2, name = 'cmp edi,63h' },
        -- cmp byte ptr [reg+offset], 63h
        { pattern = '807863', offset = 2, name = 'cmp [eax+?],63h' },
        { pattern = '807963', offset = 2, name = 'cmp [ecx+?],63h' },
        { pattern = '807A63', offset = 2, name = 'cmp [edx+?],63h' },
        { pattern = '807B63', offset = 2, name = 'cmp [ebx+?],63h' },
        { pattern = '807E63', offset = 2, name = 'cmp [esi+?],63h' },
        { pattern = '807F63', offset = 2, name = 'cmp [edi+?],63h' },
    };

    local found = 0;
    local patched = 0;
    local alreadyPatched = {};

    for _, p in ipairs(patterns) do
        local count = 0;
        local addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);

        while addr ~= 0 and count < 50 do
            local patchAddr = addr + p.offset;

            -- Check if this looks like a level check (followed by conditional jump)
            local nextByte = ashita.memory.read_uint8(addr + #p.pattern / 2);
            local isJump = (nextByte >= 0x70 and nextByte <= 0x7F) or (nextByte == 0x0F);

            local context = '';
            for i = -2, 6 do
                context = context .. string.format('%02X ', ashita.memory.read_uint8(addr + i));
            end

            -- Only process patterns followed by jumps (likely level checks)
            if isJump and not alreadyPatched[patchAddr] then
                local currentByte = ashita.memory.read_uint8(patchAddr);

                if doPatch and currentByte == ORIGINAL_LEVEL then
                    applyPatch(patchAddr, TARGET_LEVEL, p.name);
                    printMsg(string.format('  PATCHED 0x%08X: %s - %s', patchAddr, p.name, context));
                    patched = patched + 1;
                else
                    printMsg(string.format('  [JUMP] 0x%08X: %s - %s', patchAddr, p.name, context));
                end
                alreadyPatched[patchAddr] = true;
            elseif not isJump then
                debugPrint(string.format('  [----] 0x%08X: %s - %s', patchAddr, p.name, context));
            end

            found = found + 1;
            count = count + 1;
            addr = ashita.memory.find('FFXiMain.dll', 0, p.pattern, 0, count);
        end
    end

    printMsg(string.format('Scan complete. Found %d patterns total.', found));
    if doPatch then
        printSuccess(string.format('Patched %d level 99 comparisons to 75.', patched));
    else
        printMsg('Enable debug mode to see non-jump patterns: /ujp debug');
        printMsg('To patch all: /ujp patchscanall');
    end

    return patched;
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
    -- Just log for debugging, don't modify (causes visual bug)
    if e.id == 0x0061 and state.debug then
        local ptr = ffi.cast('uint8_t*', e.data_modified_raw);
        local mainJobLevel = ptr[0x0D];
        local subJobLevel = ptr[0x0F];
        debugPrint(string.format('Char Stats packet: Main Lv.%d, Sub Lv.%d', mainJobLevel, subJobLevel));
    end

    -- Packet 0x063 = miscdata
    if e.id == 0x0063 then
        local ptr = ffi.cast('uint8_t*', e.data_modified_raw);
        local subtype = ptr[0x04];

        debugPrint(string.format('Packet 0x063 subtype=%d (0x%02X)', subtype, subtype));

        -- Subtype 0x05 = Job Points Totals data
        -- DISABLED FOR TESTING: Isolating main menu patch
        --[[
        if subtype == 0x05 then
            --printMsg('*** Intercepted Job Points TOTALS packet (0x063 subtype 0x05) ***');

            local jobDataOffset = 0x0C;   -- Start of job array
            local jobEntrySize = 6;       -- Each entry is 6 bytes
            local totalJpSpentOffset = 4; -- totalJpSpent is at offset 4 within entry

            local modified = 0;
            for jobId = 1, 22 do
                local entryOffset = jobDataOffset + (jobId * jobEntrySize);
                local spentOffset = entryOffset + totalJpSpentOffset;

                local spentLow = ptr[spentOffset];
                local spentHigh = ptr[spentOffset + 1];
                local totalSpent = spentLow + (spentHigh * 256);

                if totalSpent < 100 then
                    -- Set to 100 to enable the job in the menu
                    -- 100 = 0x64 in little-endian: 64 00
                    ptr[spentOffset] = 0x64;
                    ptr[spentOffset + 1] = 0x00;
                    modified = modified + 1;
                end
            end

            if modified > 0 then
                printMsg(string.format('Modified %d jobs: totalJpSpent -> 100', modified));
            end
        end
        --]]
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
        printMsg('  /ujp list         - List all test patches and their status');
        printMsg('  /ujp on <num>     - Enable test patch #num');
        printMsg('  /ujp off <num>    - Disable test patch #num');
        printMsg('  /ujp status       - Show current patch status');
        printMsg('  /ujp scan         - Scan for level check patterns');
        printMsg('  /ujp restore      - Restore all patches');
        printMsg('  /ujp debug        - Toggle debug mode');
        return;
    end

    local cmd = args[2]:lower();

    if cmd == 'list' then
        listTestPatches();
    elseif cmd == 'on' then
        if #args < 3 then
            printError('Usage: /ujp on <num>');
            return;
        end
        local num = tonumber(args[3]);
        if num then
            applyTestPatch(num);
        else
            printError('Invalid patch number');
        end
    elseif cmd == 'off' then
        if #args < 3 then
            printError('Usage: /ujp off <num>');
            return;
        end
        local num = tonumber(args[3]);
        if num then
            removeTestPatch(num);
        else
            printError('Invalid patch number');
        end
    elseif cmd == 'status' then
        printMsg(string.format('Active patches: %d', #state.patches));
        printMsg(string.format('Debug mode: %s', state.debug and 'ON' or 'OFF'));
        if #state.patches > 0 then
            printMsg('Patches:');
            for i, p in ipairs(state.patches) do
                local addr = p.ptr or p.address or 0;
                local pattern = p.pattern or 'unknown';
                local purpose = knownAddresses[addr] or 'unknown';
                printMsg(string.format('  %d: 0x%08X [%s] (%s)', i, addr, pattern, purpose));
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
        scanAll99(false); -- Scan only, don't patch
    elseif cmd == 'patchscanall' then
        -- Patch all patterns found by scanall (those followed by jumps)
        scanAll99(true); -- Scan and patch
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
                        ({ [0xF8] = 'al', [0xF9] = 'cl', [0xFA] = 'dl', [0xFB] = 'bl' })[prev1] or 'reg');
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
        local addr = p.ptr or p.address;
        local backup = p.backup or p.original;
        
        if not addr or not backup then
            printError('Invalid patch data at index ' .. num);
            return;
        end
        
        local currentByte = ashita.memory.read_uint8(addr);

        if currentByte == TARGET_LEVEL then
            -- Currently patched, restore original
            ashita.memory.write_uint8(addr, backup);
            printMsg(string.format('Patch %d DISABLED (0x%08X now 0x%02X). Zone to test effect.', num, addr, backup));
        else
            -- Currently original, apply patch
            ashita.memory.write_uint8(addr, TARGET_LEVEL);
            printMsg(string.format('Patch %d ENABLED (0x%08X now 0x%02X). Zone to test effect.', num, addr, TARGET_LEVEL));
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
    elseif cmd == 'scan2' then
        -- New dynamic scan for level 99 patterns
        scanForPatternsv2();
    elseif cmd == 'analyze' then
        -- Analyze the main menu patch to find clues for per-job list
        analyzeMainMenu();
    elseif cmd == 'dumppattern' then
        -- Dump bytes around confirmed patches to build better patterns
        dumpPatternContext();
    elseif cmd == 'scanarray' then
        -- Search for array-indexed level checks (for per-job list)
        searchArrayPatterns();
    elseif cmd == 'searchjob' then
        -- Search for patterns with job ID + level 99
        if #args < 3 then
            printError('Usage: /ujp searchjob <jobid or name>');
            printMsg('Example: /ujp searchjob 15  (for SMN)');
            printMsg('Example: /ujp searchjob smn');
            printMsg('Job IDs: WAR=1, MNK=2, WHM=3, BLM=4, RDM=5, THF=6, PLD=7, DRK=8, BST=9, BRD=10');
            printMsg('         RNG=11, SAM=12, NIN=13, DRG=14, SMN=15, BLU=16, COR=17, PUP=18, DNC=19, SCH=20, GEO=21, RUN=22');
            return;
        end
        local jobId = tonumber(args[3]);
        if not jobId then
            -- Try to match by name
            local name = args[3]:upper();
            for id, n in pairs(jobNames) do
                if n == name then
                    jobId = id;
                    break;
                end
            end
        end
        if jobId and jobId >= 1 and jobId <= 22 then
            searchJobPattern(jobId);
        else
            printError('Invalid job ID or name');
        end
    elseif cmd == 'patchscan' then
        -- Patch a scan result (change 63h to 4Bh)
        if #args < 3 then
            printError('Usage: /ujp patchscan <num>');
            printMsg('Run /ujp scan2 or /ujp searchjob first');
            return;
        end
        local num = tonumber(args[3]);
        if num then
            patchScanResult(num);
        else
            printError('Invalid number');
        end
    elseif cmd == 'patchrange' then
        -- Patch a range of scan results
        if #args < 4 then
            printError('Usage: /ujp patchrange <start> <end>');
            printMsg('Example: /ujp patchrange 1 10  (patches #1 through #10)');
            return;
        end
        local startId = tonumber(args[3]);
        local endId = tonumber(args[4]);
        if startId and endId then
            patchScanRange(startId, endId);
        else
            printError('Invalid range');
        end
    elseif cmd == 'restorerange' then
        -- Restore a range of scan results
        if #args < 4 then
            printError('Usage: /ujp restorerange <start> <end>');
            return;
        end
        local startId = tonumber(args[3]);
        local endId = tonumber(args[4]);
        if startId and endId then
            restoreScanRange(startId, endId);
        else
            printError('Invalid range');
        end
    elseif cmd == 'scanstatus' then
        -- Show which scan results are currently patched
        showPatchedStatus();
    elseif cmd == 'nopscan' then
        -- NOP a scan result's jump
        if #args < 3 then
            printError('Usage: /ujp nopscan <num>');
            printMsg('Run /ujp scan2 first to see available patches');
            return;
        end
        local num = tonumber(args[3]);
        if num then
            nopScanResult(num);
        else
            printError('Invalid number');
        end
    elseif cmd == 'jmpscan' then
        -- Like nomad: change conditional jump to unconditional JMP
        if #args < 3 then
            printError('Usage: /ujp jmpscan <num>');
            printMsg('Run /ujp scan2 first. This changes Jcc->JMP like nomad addon');
            return;
        end
        local num = tonumber(args[3]);
        if num then
            jmpScanResult(num);
        else
            printError('Invalid number');
        end
    else
        printError('Unknown command: ' .. cmd);
        printMsg('Use /ujp help for command list.');
    end
end);
