--[[
* Unlock Job Points Menu at Level 75
*
* Uses pattern scanning to find and patch level checks.
* Focus: Main Menu Access
--]]

addon.name    = 'unlockjobpoints';
addon.author  = 'FFXI-Ashita';
addon.version = '4.1.0';
addon.desc    = 'Unlocks the Job Points menu at level 75';
addon.link    = 'https://github.com/kchang4/unlockjobpoints';

require('common');
local chat = require('chat');

-- Constants
local TARGET_LEVEL = 75;   -- Level we want to enable JP menu at
local ORIGINAL_LEVEL = 99; -- Original retail level requirement

--[[
* Core Patterns for Main Menu Access
--]]
local PATTERNS = {
    -- 1. JP Menu Enable Check - The main gate for the menu
    -- Pattern: CMP EAX, 50h (80); JB ...; CMP EAX, 99
    {
        pattern = '83F850720883F8??',
        offset = 7,
        name = 'JP Menu Enable Check',
    },
    -- 2. JP Menu Init Check - Initialization of the menu
    -- Pattern: XOR CL,CL; CMP EAX, 99; MOV [ESI], ...
    {
        pattern = '32C983F8??C706',
        offset = 4,
        name = 'JP Menu Init Check',
    },
    -- 3. Per-Job Level Check - Enables individual jobs inside the menu
    -- Pattern: MOV EAX,[ESP+0C]; CMP AL, 99; JNE ...
    {
        pattern = '8B44240C3C??753B',
        offset = 5,
        name = 'Per-Job Level Check',
    }
};

local state = {
    patches = {},
    debug = false,
};

-- Print helpers
local function printMsg(msg) print(chat.header(addon.name):append(chat.message(msg))); end
local function printError(msg) print(chat.header(addon.name):append(chat.error(msg))); end
local function printSuccess(msg) print(chat.header(addon.name):append(chat.success(msg))); end

--[[
* Find ALL addresses matching a pattern
--]]
local function findAllPatternMatches(patternDef)
    local results = {};
    local seen = {};
    local searchStart = 0;
    local maxSearches = 100;
    local searches = 0;

    if not patternDef.pattern then return results; end

    while searches < maxSearches do
        local rawAddr = ashita.memory.find('FFXiMain.dll', searchStart, patternDef.pattern, 0, 0);
        if rawAddr == 0 then break; end

        local addr = rawAddr + patternDef.offset;
        if not seen[addr] then
            seen[addr] = true;
            local byteVal = ashita.memory.read_uint8(addr);
            -- Only match if it's 99 or 75
            if byteVal == ORIGINAL_LEVEL or byteVal == TARGET_LEVEL then
                table.insert(results, addr);
            end
        end
        searchStart = rawAddr + 1;
        searches = searches + 1;
    end
    return results;
end

--[[
* Apply patches
--]]
local function applyPatches()
    state.patches = {};
    local applied = 0;

    for _, p in ipairs(PATTERNS) do
        local addresses = findAllPatternMatches(p);
        if #addresses == 0 then
            printError('Pattern not found: ' .. p.name);
        else
            for _, addr in ipairs(addresses) do
                local currentByte = ashita.memory.read_uint8(addr);
                if currentByte == ORIGINAL_LEVEL then
                    table.insert(state.patches, { addr = addr, backup = currentByte, name = p.name });
                    ashita.memory.write_uint8(addr, TARGET_LEVEL);
                    applied = applied + 1;
                elseif currentByte == TARGET_LEVEL then
                    table.insert(state.patches, { addr = addr, backup = ORIGINAL_LEVEL, name = p.name });
                end
            end
        end
    end
    return applied;
end

--[[
* Restore patches
--]]
local function restorePatches()
    for _, p in ipairs(state.patches) do
        ashita.memory.write_uint8(p.addr, p.backup);
    end
    state.patches = {};
end

--[[
* Read bytes helper
--]]
local function readBytesAround(addr, before, after)
    local bytes = {};
    for i = -before, after do
        table.insert(bytes, string.format('%02X', ashita.memory.read_uint8(addr + i)));
    end
    return table.concat(bytes, '');
end

--[[
* Events
--]]
ashita.events.register('load', 'load_cb', function()
    printMsg('v' .. addon.version .. ' loaded. Scanning for Main Menu patterns...');
    local applied = applyPatches();
    if applied > 0 then
        printSuccess(string.format('Patched %d checks. Try opening the menu!', applied));
    else
        printMsg('No new patches applied (already patched or not found).');
    end
end);

ashita.events.register('unload', 'unload_cb', function()
    restorePatches();
end);

ashita.events.register('command', 'command_cb', function(e)
    local args = e.command:args();
    if #args == 0 or args[1]:lower() ~= '/ujp' then return; end
    e.blocked = true;
    local cmd = (#args > 1) and args[2]:lower() or 'help';

    if cmd == 'status' then
        printMsg('Patch Status:');
        for i, p in ipairs(state.patches) do
            printMsg(string.format('  %d. %s (0x%08X): PATCHED', i, p.name, p.addr));
        end
    elseif cmd == 'scanall' then
        printMsg('Scanning for ALL level 99 comparisons...');
        local patterns = {
            { sig = '3C63', name = 'CMP AL, 99' },
            { sig = '83F863', name = 'CMP EAX, 99' },
            { sig = '807E??63', name = 'CMP [ESI+?], 99' },
            { sig = '83??63', name = 'CMP reg, 99' },
            { sig = '80??63', name = 'CMP byte, 99' },
        };
        local found = {};
        for _, pat in ipairs(patterns) do
            local addr = 0;
            repeat
                addr = ashita.memory.find('FFXiMain.dll', addr + 1, pat.sig, 0, 0);
                if addr ~= 0 then
                    local ctx = readBytesAround(addr, 4, 4);
                    printMsg(string.format('  Found 0x%08X: %s [%s]', addr, ctx, pat.name));
                end
            until addr == 0;
        end
    elseif cmd == 'bytes' and args[3] then
        local addr = tonumber(args[3]);
        if addr then
            printMsg(string.format('Bytes at 0x%08X: %s', addr, readBytesAround(addr, 8, 8)));
        end
    end
end);
