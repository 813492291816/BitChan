# Release Checklist

 - Manual update
   - Make changes to MANUAL.md
   - Don't change ```<!-- Replace with text formatting -->``` or ```<!-- Replace with text functions -->``` in MANUAL.md
   - Generate manual with scripts_dev/generate_manual_html.sh
 
 - Database update
   - Use incrementing alembic version for database/alembic/versions upgrade script
     - Set proper down_revision of new upgrade script
     - Use post_alembic_write() to initiate execution of post-database-upgrade
     - Add post-database-upgrade changes to database/upgrade_database_post.py
   - Change config.VERSION_ALEMBIC to the latest version

 - Config update
   - increment config.VERSION_BITCHAN
   - If message version incompatibility, set config.VERSION_MIN_MSG to config.VERSION_BITCHAN

  - Commit release code to master branch
  - Create release with ```vX.X.X``` tag and copy changelog
  
 - Sign binaries/archives
   - ```gpg --armor --detach-sign file```
   - Attach to release
   - Verify with ```gpg --verify file.asc```
