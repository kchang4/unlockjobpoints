# UnlockJobPoints - Ashita v4 Addon

Unlocks the Job Points menu at level 75 for 75-era FFXI private servers.

## The Problem

The FFXI client has a hardcoded check that requires level 99 to enable the Job Points menu:

```cpp
if (PTR_status_data.MainJobLevel >= 99u && (flags & 1) != 0)
{
    FUNC_CTkMenuCtrlData_SetButtonStatus(..., TK_MENUCTRL_ENABLE, 12);
}
```

Even if the server sends the correct flags, the client blocks access at lower levels.

## Solutions

This addon provides two approaches:

### 1. Memory Patch (Primary) - `unlockjobpoints.lua`

Patches the client's memory to change the level check from 99 to 75.

**Pros:**
- Level displays correctly (shows your real level 75)
- Clean implementation
- Other systems see your correct level

**Usage:**
```
/addon load unlockjobpoints
```

### 2. Packet Spoof (Fallback) - `unlockjobpoints_fallback.lua`

Spoofs the player level to 99 in incoming packets.

**Cons:**
- Your level displays as 99 in the client UI
- All systems that read level will see 99

**Usage:**
```
# Rename fallback to main:
# unlockjobpoints.lua → unlockjobpoints_memory.lua
# unlockjobpoints_fallback.lua → unlockjobpoints.lua
/addon load unlockjobpoints
```

## Commands

- `/ujp help` - Show all commands
- `/ujp status` - Show current patch status
- `/ujp scan` - Scan for level 99 patterns (memory version)
- `/ujp patch <hex>` - Manually patch address
- `/ujp restore` - Restore original bytes
- `/ujp debug` - Toggle debug output

## Troubleshooting

### "Could not find level check patterns"

The pattern search may not find the correct location. Try:

1. **Enable debug mode:** `/ujp debug`
2. **Run scan:** `/ujp scan`
3. **Report results** on Ashita Discord

If scanning finds patterns but they don't work:
- Different client versions have different offsets
- Ask on Ashita Discord for known patterns

### Use the fallback if needed

If memory patching doesn't work, use the fallback version:
1. Rename `unlockjobpoints.lua` to `unlockjobpoints_memory.lua`
2. Rename `unlockjobpoints_fallback.lua` to `unlockjobpoints.lua`
3. Reload: `/addon reload unlockjobpoints`

### Menu still locked

Make sure:
1. Server sent the `JOB_BREAKER` key item
2. Server configured `JOB_POINTS_PLAYER_LEVEL = 75`
3. Try zoning to refresh menu state

## Server Configuration

On LandSandBoat servers, add to `settings/server/map.lua`:

```lua
JOB_POINTS_PLAYER_LEVEL = 75,
JOB_POINTS_MOB_LEVEL = 75,
JOB_POINTS_GIFT_MULTIPLIER = 0.5,
```

## Technical Details

### Memory Patch Approach

The addon uses `ashita.memory.find()` to search for assembly patterns that compare against 99 (0x63):

- `80 7E ?? 63` - `cmp byte ptr [esi+offset], 63h`
- `3C 63` - `cmp al, 63h`
- etc.

When found, it changes the immediate value from `0x63` (99) to `0x4B` (75).

### Packet Spoof Approach

Modifies incoming packet 0x0061 (CLISTATUS) to change the level byte at offset 0x0D from the real value to 99.

## Files

- `unlockjobpoints.lua` - Main addon (memory patch approach)
- `unlockjobpoints_fallback.lua` - Fallback addon (packet spoof approach)

## License

GNU General Public License v3.0
