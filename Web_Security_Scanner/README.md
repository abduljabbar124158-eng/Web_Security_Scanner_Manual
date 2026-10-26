# Web Security Scanner (Manual Start)

A local Python web dashboard for preliminary website security checks. No third-party packages are required.

## Windows: run manually (no BAT/EXE files)

1. Extract this ZIP to a normal folder, such as Documents\Web_Security_Scanner.
2. Open that folder in File Explorer.
3. Click the address bar, type `cmd`, and press Enter. This opens Command Prompt in the project folder.
4. Check Python is available:

   `py --version`

   If that command is unavailable, try `python --version`. If neither works, install Python from the official Python website and enable **Add Python to PATH** during setup.

5. Start the dashboard:

   `py web_app.py`

   Or, if your system uses `python`:

   `python web_app.py`

6. Keep the Command Prompt window open. Open your browser and visit **http://127.0.0.1:8080**.
7. Enter a website URL and select **Scan website**. Download the HTML report from the results page.
8. To stop the dashboard, return to Command Prompt and press **Ctrl+C**.

## Optional: test the scanner from the command line

`py scanner.py https://example.com`

This creates `security_report.html` in the current folder. Replace the example URL with a website you own or are authorized to test.

## Optional local demo server

For a local sample page, open a second Command Prompt in this folder and run:

`py demo_server.py`

Then run the command-line scanner against `http://127.0.0.1:8000`. The dashboard intentionally blocks local hostnames.

## Safety and limitations

Only scan websites you own or have explicit permission to assess. This is an educational, limited first-pass scanner, not a full vulnerability scanner. Results can include false positives or false negatives and should be reviewed manually.
