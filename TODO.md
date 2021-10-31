# TODO

## To be completed before next release

 - None

# Bugs

 - None

# Ideas

 - add ~~exporting~~ and importing to preserve address book, identities, lists, and boards
 - include upload methods in exporting/importing
 - allow owners/admin to reverse bans
 - allow ban durations
 - move board and list links side by side (2 columns)
 - allow boards/lists to have categories (to group together)
 - allow changing board/list label
 - refresh threads for new board joiners, either automatically or manually. Posting with an identity will be required to authenticate the sender. Anyone receiving the refreshed messages who already has one will see no change, but anyone who doesn't have a message will see it appear. This is more crucial for OPs than replies. The refresh function will preserve the original timestamp. If a recipient of a refreshed post previously deleted reply, it should stay deleted (deleted post IDs are currently logged in a database until the message TTL expires).
 - when someone goes to reply by clicking a post id and has text highlighted in that post to which he is replying, that text should be copied below the message id in the body of the reply's comment box. The cursor in the message box should appear on a new line below the copied, highlighted text.
 - allow local deletion of images on posts and prevent them from being redownloaded (locally blacklist a message ID).
 - allow ability to sort messages by sent or received time
 - add post tree view
 - add page for managing PGP keyring, public/private keys
 - add support for PGP signatures of posts or messages within posts
 - allow conversion to 12-hour time display
 - add option for auto-loop and default volume for audio/video files
 - add "a new reply to your post" desktop notifications
 - report board: Any user can report a post in an imageboard chan and it will get duplicated and sent to a report chan. The reported post can include a reason why it was reported. A board owner could create a report board and set it as a permission of a newly-created board. The owner/admin could track the status of the board without having to monitor every post in every thread of a board. This tracking, provided by the user generated reports, can allow the owner/admin to decide whether the posting rules need to be updated or if the board should be abandoned for a new one.
 - more board rules: pictures or other files could be disabled, message length
 - add post editing (non-board addresses only)
 - add list of watched threads
 - add "last 100" thread view. Only load the last 100 posts plus the OP appears at the top.
 - add "expand all images" button
 - add bell icon in top right indicating a new software version is available
 - allow owners/admins to see the from address of an item on a list, for banning/restricting purposes
 - allow owners/admins to add text under posts (post content cannot be modified but a custom message can be added below it, e.g. "USER WAS BANNED FOR THIS POST...")
 - allow users to locally undo owner/admin moderation
 - allow for user initiated global delete of posts for which he has a password. Allow for the entry of passwords during the composition of a message. Perhaps owners can have a rule dis/allowing user initiated post deletes.
 - allow for a forwarder address for a board. Users send messages directly to an address from which all posts come. Modes: off, strict, relaxed
 - add an option to allow removal of a file after download or a button to clear all downloads or both options?
 - allow custom banners: externally hosted banners? multiple cycling banners by uploading a zip? movie banners? large file banners?
 - sfw/nsfw labels for boards
 - investigate whether Peertube could be an alternative to Youtube/Invidious
 - investigate what if any use Filecoin could have
 - gather unjoined board/list passphrases posted on all joined boards into a list and present it on the home page so the user can easily join them if they want.
 - write full BitChan build instructions for ARM, POWER9 and RISC-V, and the other Free Hardware architectures.
 - can ed25519 or better (post-quantum quality curves) be used
 - Link TTL to auto wipe and add 6hrs for messages sent in boards with auto wipe by default
 - check for .onion BM bootstrap
 - thumbnail of video OPs for home page
 - allow owner selected custom spoiler images
 - could omemo or some form of double ratchet be used?
 - bulk delete boards/lists/identities/address book entries
 - add a message PGP, attachment PGP and steg PGP passphrase manager and allow trying to decrypt every message, attachment and steg with each stored passphrase.
 - allow sending mail to multiple addresses at once
 - allow lists featured on the homepage to display custom banner pic like boards display OP's pic
 - put flags inside a scrollable area if there's more than 5
 - put upload sites inside a scrollable area if there's more than 5
 - make ID/address section in the board/list creation page collapsible after if entries are greater than a certain number
 - The greyed out (in dark theme anyway) unlinked board/list name that occurs when you're in a board/thread/list should still be linked so that when you are at the bottom of a thread, board index or list you can click it and reload that page.
 - thread watch list
