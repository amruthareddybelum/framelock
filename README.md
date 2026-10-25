# FrameLock Prototype

A Streamlit demo for file fingerprinting and a hash-linked audit timeline.

## Run locally

Python 3.10+ recommended.

### Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

If `py` is not recognized, replace `py` with `python`.

## Demo flow
1. Create a text file containing `Camera sample A`.
2. Open **Register Evidence** and register the file.
3. Open **Verify Evidence** and upload the same file: expect **MATCH**.
4. Edit a copy to contain `Camera sample B`; verify against the original record: expect **MISMATCH**.
5. Open **Audit Timeline** to inspect the hash-linked events.

## Deploy publicly
Upload `app.py`, `requirements.txt`, and `README.md` to a GitHub repository. Then create an app at https://share.streamlit.io/ and select `app.py` as the entrypoint.

## Important limitations
This is a demonstration prototype. It does not establish that evidence is authentic or truthful, and it does not deploy a real blockchain. SQLite data may not persist reliably on hosted ephemeral storage. Do not upload confidential or sensitive evidence.
