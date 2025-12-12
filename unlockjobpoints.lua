--[[
* Unlock Job Points Menu at Level 75
*
* Patches two specific addresses to enable the Job Points menu at level 75:
*   1. 0x046D84F7 - Job Points Menu Main Check (enables menu access)
*   2. 0x046D9BA6 - Per-Job Level Check (enables individual jobs in menu)
--]]

addon.name    = 'unlockjobpoints';
addon.author  = 'FFXI-Ashita';
addon.version = '3.0.0';
addon.desc    = 'Unlocks the Job Points menu at level 75';
addon.link    = 'https://github.com/kchang4/unlockjobpoints';

require('common');
local chat = require('chat');
local ffi = require('ffi');

-- Constants
local TARGET_LEVEL = 0x4B;   -- 75 in hex
local ORIGINAL_LEVEL = 0x63; -- 99 in hex

-- The two addresses that unlock Job Points at level 75
-- These are the actual memory addresses (not RVAs)
local PATCH_ADDRESSES = {
    { addr = 0x046D84F7, name = 'JP Menu Main Check' },
    { addr = 0x046D9BA6, name = 'Per-Job Level Check' },
};

-- State
local state = {
    patches = {}, -- {addr, backup, name}
    debug = false,
};

--[[
* Print helpers
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

--[[
* Apply patches to enable JP menu at level 75
--]]
local function applyPatches()
    state.patches = {};
    local applied = 0;

    for _, p in ipairs(PATCH_ADDRESSES) do
        local currentByte = ashita.memory.read_uint8(p.addr);

        if currentByte == ORIGINAL_LEVEL then
            -- Store backup and patch
            table.insert(state.patches, {
                addr = p.addr,
                backup = currentByte,
                name = p.name
            });
            ashita.memory.write_uint8(p.addr, TARGET_LEVEL);
            applied = applied + 1;
            if state.debug then
                printMsg(string.format('  Patched %s (0x%08X): 0x63 -> 0x4B', p.name, p.addr));
            end
        elseif currentByte == TARGET_LEVEL then
            -- Already patched, just track it
            table.insert(state.patches, {
                addr = p.addr,
                backup = ORIGINAL_LEVEL,
                name = p.name
            });
            if state.debug then
                printMsg(string.format('  %s (0x%08X): already patched', p.name, p.addr));
            end
        else
            printError(string.format('  %s (0x%08X): unexpected value 0x%02X', p.name, p.addr, currentByte));
        end
    end

    return applied;
end

--[[
* Restore original bytes
--]]
local function restorePatches()
    local restored = 0;
    for _, p in ipairs(state.patches) do
        ashita.memory.write_uint8(p.addr, p.backup);
        restored = restored + 1;
    end
    state.patches = {};
    return restored;
end

--[[
* Event: load
--]]
ashita.events.register('load', 'load_cb', function()
    printMsg('v' .. addon.version .. ' loaded');

    local applied = applyPatches();
    if applied > 0 then
        printSuccess(string.format('Patched %d address(es). Job Points menu enabled at 75!', applied));
    else
        printMsg('Patches already applied or addresses not found.');
    end
end);

--[[
* Event: unload
--]]
ashita.events.register('unload', 'unload_cb', function()
    restorePatches();
    printMsg('Patches restored. Addon unloaded.');
end);

--[[
* Event: command
--]]
ashita.events.register('command', 'command_cb', function(e)
    local args = e.command:args();
    if #args == 0 or args[1]:lower() ~= '/ujp' then
        return;
    end
    e.blocked = true;

    local cmd = (#args > 1) and args[2]:lower() or 'help';

    if cmd == 'help' then
        printMsg('Commands:');
        printMsg('  /ujp status  - Show patch status');
        printMsg('  /ujp patch   - Apply patches');
        printMsg('  /ujp restore - Restore original bytes');
        printMsg('  /ujp debug   - Toggle debug mode');
    elseif cmd == 'status' then
        printMsg(string.format('Patches tracked: %d', #state.patches));
        for i, p in ipairs(state.patches) do
            local current = ashita.memory.read_uint8(p.addr);
            local status = (current == TARGET_LEVEL) and 'PATCHED' or 'ORIGINAL';
            printMsg(string.format('  %d. %s (0x%08X): %s', i, p.name, p.addr, status));
        end

        -- Also show current state of target addresses
        printMsg('Target addresses:');
        for _, p in ipairs(PATCH_ADDRESSES) do
            local current = ashita.memory.read_uint8(p.addr);
            local status = (current == TARGET_LEVEL) and 'ENABLED (0x4B)' or
                (current == ORIGINAL_LEVEL) and 'DISABLED (0x63)' or
                string.format('UNKNOWN (0x%02X)', current);
            printMsg(string.format('  %s: %s', p.name, status));
        end
    elseif cmd == 'patch' then
        local applied = applyPatches();
        if applied > 0 then
            printSuccess(string.format('Applied %d patch(es).', applied));
        else
            printMsg('Patches already applied.');
        end
    elseif cmd == 'restore' then
        local restored = restorePatches();
        printMsg(string.format('Restored %d patch(es).', restored));
    elseif cmd == 'debug' then
        state.debug = not state.debug;
        printMsg(string.format('Debug mode: %s', state.debug and 'ON' or 'OFF'));
    else
        printError('Unknown command. Use /ujp help');
    end
end);

-- Cleanup handler for crashes
local gc = ffi.gc(ffi.cast('uint8_t*', 0), function()
    restorePatches();
end);
