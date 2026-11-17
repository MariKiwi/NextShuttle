# Links, codes, keys and passwords

## Recommended: full link + transfer password

Copy **Copy full link** from Your transfers and send the recipient the link. Send the **transfer password** separately. Opening the link fills the code and includes the encryption key automatically; no separate key entry is needed. A complete code pasted into the public form works the same way.

## Alternative: share code + key + password

The separate share code identifies and authorizes the transfer, but omits its key. Supply the separate encryption key and transfer password as well. All three are required for new transfers. The download key is a random secret. For upload inboxes the displayed encryption key is a public encryption key; the private decryption key stays in Nextcloud. A link/code is still sensitive access information.

The password is a distinct encryption factor, never your Nextcloud password or relay administrator login. Knowing or guessing the code alone cannot decrypt the new-format download. Keep the full link private too: the password is not a reason to publish it.

## Choosing a password

When creating a share/inbox, choose **Set my own password** (default) or **Generate a random password**. Your password must meet the administrator's minimum length (at least 16 characters). Random mode offers a regenerate button. Both modes provide copy/show controls. Save the password from the creation confirmation before closing it: Your transfers does not show it later.

For upload inboxes this is the reusable upload password. Changing it creates a new code/link, so send the updated information to recipients.

Legacy transfers keep their old protection and are labelled. Recreate them for password-bound encryption.
