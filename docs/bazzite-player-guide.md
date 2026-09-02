# Bazzite setup: step-by-step beginner guide

This guide is for the **original retail Homeworld** and **Homeworld: Cataclysm / Emergence**. It is written for someone who has never used a Linux terminal before.

You do **not** need to know Linux commands. You will copy and paste one command.

> **Important:** Homeworld Remastered Collection's built-in classic game is not supported by this installer.

## Part 1: Add the game to Steam

Do this separately for each game you want to use online.

1. Open **Steam**.
2. At the bottom-left corner, select **Add a Game**.
3. Select **Add a Non-Steam Game**.
4. Select **Browse**.
5. Find and select the game file:
   - Homeworld: `Homeworld.exe` or `homeworld.exe`
   - Cataclysm / Emergence: `Cataclysm.exe` or `cataclysm.exe`
6. Select **Add Selected Programs**.
7. Find the new game in your Steam Library.
8. Right-click it and select **Properties**.
9. Select **Compatibility**.
10. Turn on **Force the use of a specific Steam Play compatibility tool**.
11. Choose a recent **Proton** version from the box below it.
12. Close the Properties window.
13. Select **Play**. Wait until the game opens, then close the game.

Do not continue until the game can open from Steam. Opening it once creates the Proton folder that the setup program needs.

## Part 2: Install Protontricks

1. Open Bazzite's application menu. This is the menu you normally use to open programs.
2. Open **Discover**.
3. Click the search box and type `Protontricks`.
4. Select **Protontricks**, then select **Install**.
5. Close Discover when installation finishes.

If Discover says Protontricks is already installed, that is fine.

## Part 3: Download and unzip the setup program

1. Open the project's [GitHub Releases page](https://github.com/FlashZ/homeworld-classic-online/releases).
2. Open the newest release.
3. Under **Assets**, download the file whose name starts with `RetailWONSetup-linux-` and ends with `.zip`.
4. Open the **Downloads** folder in Bazzite's file manager. The file manager is named **Dolphin**.
5. Right-click the downloaded ZIP file.
6. Select **Extract**, then **Extract archive here**.
7. A new folder whose name starts with `RetailWONSetup-linux-` will appear. Double-click that new folder to open it.

Do not run a script by double-clicking it. Bazzite may appear to do nothing. Use the next part instead.

## Part 4: Open the terminal in the correct folder

Keep the extracted `RetailWONSetup-linux-...` folder open in Dolphin.

1. Right-click an empty area inside that folder. Do not right-click a file.
2. Select **Open Terminal Here**.

A dark window named **Konsole** will open. Konsole is Bazzite's terminal. The words before the blinking cursor do not need to match anyone else's computer.

If **Open Terminal Here** is not shown, press **F4** while the folder is open. A terminal panel will appear at the bottom of Dolphin.

## Part 5: Run the setup

1. Copy this entire line:

   ```bash
   bash installer/install-bazzite.sh
   ```

2. Click inside Konsole.
3. Paste with **Ctrl+Shift+V**. Ordinary Ctrl+V may not paste in a terminal.
4. Press **Enter**.
5. Read each question and type the requested answer:
   - Type `1` for Homeworld.
   - Type `2` for Cataclysm / Emergence.
   - When asked for the game folder, drag the folder containing the game's `.exe` file from Dolphin into Konsole, then press Enter.
   - If it asks for a shortcut number, find the line beginning with **Non-Steam shortcut**. Type only the number in parentheses, then press Enter.
   - Type `y` if you want the optional multiplayer maps. Otherwise, press Enter.
6. Wait. Warnings containing the word `WARNING` are usually harmless.

The last message should say:

```text
SETUP FINISHED SUCCESSFULLY
```

The setup creates a CD key automatically when the game does not already have one. You do not need to create or type a key yourself.

## Part 6: Play online

1. Close Konsole.
2. Open Steam.
3. Start the game from the **same non-Steam shortcut** you used earlier.
4. Open the game's **Internet** screen.
5. Create an account or sign in.

For Cataclysm / Emergence, select **Cancel** when the optional account-details screen asks for an email address, country, and ZIP code. Then select **Create New Account** and **Launch WON**.

## Setting up the other game

Run the same setup again:

```bash
bash installer/install-bazzite.sh
```

Choose the other game when it asks. Homeworld and Cataclysm use separate Steam shortcuts and separate CD keys.

## If it does not work

Do not paste ordinary sentences from Discord into Konsole. Paste only text shown inside a command box like the one above.

Take one clear picture showing the **bottom of the Konsole window**, including the last error message. Also say:

- whether you chose Homeworld or Cataclysm;
- whether the game opens from Steam;
- whether the game is stored on the Bazzite drive or another drive.

The game may be stored on another drive. It does not need to be on the same drive as Bazzite.
