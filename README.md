# UnlockJobPoints - Ashita v4 Addon

Unlocks the Job Points menu at level 75 for 75-era FFXI private servers.

## The Problem

The FFXI client has a hardcoded check that requires level 99 to enable the Job Points menu. Even if the server sends the correct flags, the client blocks access at lower levels.

## Solution

This addon patches the client's memory to change the level check from 99 to 75. Your level displays correctly - no spoofing needed.

## Installation

Copy the `unlockjobpoints` folder to `Ashita/addons/`

## Usage

```
/addon load unlockjobpoints
```

## Commands

| Command | Description |
|---------|-------------|
| `/ujp status` | Show active patches |
| `/ujp scan` | Scan for level 99 patterns |
| `/ujp test <num>` | Toggle patch #num on/off |
| `/ujp restore` | Restore all patches |
| `/ujp debug` | Toggle debug output |

## Server Configuration

On LandSandBoat servers, add to `settings/server/map.lua`:

```lua
JOB_POINTS_PLAYER_LEVEL = 75,
JOB_POINTS_MOB_LEVEL = 75,
JOB_POINTS_GIFT_MULTIPLIER = 0.5,
```

You also need to grant the `JOB_BREAKER` key item to players.

## Known Patches

| Address | Purpose |
|---------|---------|
| `0x045184F7` | Job Points Menu |
| `0x0459A605` | Unknown (level check) |
| `0x047338F9` | Unknown (level check) |

*Note: Addresses may vary by client version.*

## License

GNU General Public License v3.0
