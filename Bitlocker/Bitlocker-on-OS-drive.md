## How to enable BitLocker with pre-boot PIN (Windows 10/11)

### **Prerequisites**

* Device must have a TPM (most modern devices do).
* You must be logged in as Administrator.

---

## **Step 1 — Enable the group policy settings for pre-boot authentication**

1. Press **Win + R** → type:
   `gpedit.msc`
   and press Enter.
2. Go to:
   **Computer Configuration → Administrative Templates → Windows Components → BitLocker Drive Encryption → Operating System Drives**
3. Double-click:
   **Require additional authentication at startup**
4. Set it to **Enabled**.
5. Ensure that the option **Allow BitLocker without a compatible TPM** is **unchecked** (unless you plan to use BitLocker without TPM).
6. Under "Configure TPM startup PIN", select **Require startup PIN with TPM**.
7. Click **OK**.

Optional: It is possible to add GPO setting to use enchased symbol set. By default, BitLocker only allows **numeric** PINs (0–9) for pre-boot authentication.

**Enhanced PIN** allows:

* uppercase and lowercase letters
* numbers
* punctuation
* special characters
* spaces

Note!

* Enhanced PINs can be up to **20 characters**.
* Make sure the keyboard layout during pre-boot matches what you expect (typically US layout).
* Avoid characters that move between layouts if you use a non-US keyboard.

Locate and double-click in the same policy tree:  **Allow enhanced PINs for startup**  and set the policy to: **Enabled**


---

## **Step 2 — Apply policy updates**

1. Open Command Prompt as Administrator.
2. Run:
   `gpupdate /force`

---

## **Step 3 — Change BitLocker settings to enable the Startup PIN**

### If BitLocker is not yet enabled:

1. Open **Control Panel → BitLocker Drive Encryption**.
2. Click **Turn on BitLocker** for the system drive.
3. When prompted, select **Enter a PIN**.
4. Set the pre-boot PIN.
5. Complete the setup and reboot when required.

### If BitLocker is already enabled:

1. Open **Control Panel → BitLocker Drive Encryption**.
2. Next to the system drive, click **Change how drive is unlocked at startup**.
3. Click **Add a PIN**.
4. Set the desired PIN.
5. Reboot to confirm.

NOTE: You can use cmd to set the PIN: 
`
manage-bde -protectors -add C: -TPMAndPIN
`
or to change the existing PIN:
`
manage-bde -changepin C:
`

---

## **Step 4 — Verify the configuration**

After reboot:

* Before Windows starts, you should see a **BitLocker PIN** prompt.
* Only after entering the PIN will the system begin decrypting and loading the OS.

---

## QA If a someone steals the laptop (with bitlocker enabled but without PIN) and does not know the Windows password, can they read the data?

**If BitLocker is enabled: generally no.**

More precisely:

### Case 1: BitLocker is enabled in default mode (TPM-only)

* The disk is fully encrypted.
* Simply removing or resetting the Windows password does **not** give access to the data.
* Booting from external media also does **not** give access because the disk remains encrypted.

However:

* If the thief powers on the laptop normally, the TPM may automatically release the decryption key and Windows will boot.
* At that point the Windows logon screen appears.
* If they do not know the Windows password, they still **cannot** authenticate and cannot read the data.

This configuration **protects against offline attacks**, but it does not prevent someone from turning on the laptop and having it decrypt automatically before the logon screen.

To block this scenario, use a pre-boot PIN.

---

### Case 2. With a BitLocker pre-boot PIN enabled

If pre-boot PIN is enabled (TPM + PIN mode):

* When the device is powered on, BitLocker prompts **before Windows loads**.
* If the thief does not know the PIN, TPM will not release the decryption key.
* The operating system will not start.
* The disk remains fully encrypted and unreadable.

This is the strongest practical configuration for protecting data in case of device theft.


Below is the exact procedure to enable and use **Enhanced PINs** for BitLocker pre-boot authentication (i.e., PINs that include letters, symbols, and spaces instead of being limited to digits).

