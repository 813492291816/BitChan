# Bugs

 - If attempting to post a message with a lot of text (>4096K) and the message has an error that returns it to the user, a "cookie too large" error is produced.
 - Dark theme need some work.

# Ideas

 - Lock thread (Owner/admin set permissions to prohibit/allow users to respond).
 - Sticky thread (Owner/admin set permissions to keep thread at top of board).
 - Display a catalog of threads from all boards, ordered by most recent post.
 - Display a catalog of all threads per board, ordered by most recent post.
 - Board/list categories (group boards or lists together).
 - Set custom board/list labels.
 - Create mailbox page for identities (inbox/sent/trash for each identity).
 - Send messages to other user addresses (from mailbox and directly from posts).
 - If user is already a member of a board that is linked in a message, provide the label/description with the link rather than merely an address.
 - Allow formatting of board/list passphrases to show a link to join the board/list rather than the whole passphrase. 
 - Set board/list-specific PGP passphrases (for both messages and steg).
 - Refresh threads for newcomers/stragglers, either automatically or manually. Posting with an identity will be required to authenticate the sender. Anyone receiving the refreshed messages who already has one will see no change, but anyone who doesn't have a message will see it appear. This is more crucial for OPs than replies. The refresh function will preserve the original timestamp. If a recipient of a refreshed post previously deleted reply, it should stay deleted (deleted post IDs are currently logged in a database until the message TTL expires).
 - Settable message time to live (TTL).
 - When someone goes to reply by clicking a post id and has text highlighted in that post to which one is replying, that text should be copied below the message id in the body of the reply's comment box.
 - Allow a way to delete images on posts and prevent them from being redownloaded (i.e. locally blacklist a message ID).
 - Add ability to sort messages by sent/received time.
 - Add post tree view.
 - Create page for managing PGP keyring, public/private keys.
 - Add support for PGP signatures.
 - Add an option to convert time stamp in the post to 12 hour time display. Maybe display both sent and received time.
 - Add option for auto-loop and default volume on video files.
 - Reply desktop notifications: Show a notification when you get a reply in an open thread while you don't have the thread's window focused.
 - Report board: Any user can report a post in an imageboard chan and it will get duplicated and sent to a report chan. The reported post can include a reason why it was reported. A board owner could create a report board and set it as a permission of a newly-created board. The owner/admin could track the status of the board without having to monitor every post in every thread of a board. This tracking, provided by the user generated reports, can allow the owner/admin to decide whether the posting rules need to be updated or if the board should be abandoned for a new one.
 - More board rules: word bans, pictures or other files could be disabled, message length.
 - Post editing (non-board addresses only).
 - A 'no bump' and 'anchor' option: Allow OPs and repliers the option to NOT bump a thread. Anchoring a thread means that no post can bump a thread. This usually happens when a thread is low quality but not so low as to warrant being deleted. The owner/admin should be allowed to change the thread status to anchored. Also, regular users should be able to, in addition to hiding or deleting a thread, anchor it. In tandem with this, or if anchoring is not possible, allow users to have a list of threads that they are watching.
 - Enable users to have a list of watched threads.
 - "Last 100" thread view. Only load the last 100 posts plus the OP appears at the top.
 - "Expand all images" button.
 - Allow the 'name' in a post header to be clickable. Clicking it allows adding it to the address book with a label. If the name has a label, display the label instead of a portion of the BMID. If the 'name' already has a label, clicking it again allows on-the-fly relabeling.
 - Add a clickable clipboard button on each message header for copying a cross-link formatted string to easily share posts from other boards.
 - Bell icon in top right indicating a newer version is available. When clicked take user to upgrade instructions and a changelog.
 - Allow owners of public lists to see the from address of who added an item to a list for banning/restricting purposes.
 - Allow Owners/Admins to add god text underneath posts. The post content can be preserved but the Owner/Admin can add a custom message below it like, "USER WAS BANNED [optional: by Owner/Admin] FOR THIS POST".
 - Allow an import/export system so preserve address book, identities, lists and boards. This could be useful for if someone is worried they'll lose this information during an upgrade for OS change etc.
