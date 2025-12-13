#!/bin/sh

RUN="java -Xmx256m -cp /app/biglybt/BiglyBT.jar:/app/biglybt/commons-cli.jar --illegal-access=deny --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED -Djava.library.path=/app/biglybt -Dazureus.install.path=/app/biglybt -Dazureus.script=/app/biglybt/biglybt -Dazureus.script.version=10 -DMULTI_INSTANCE=true -Daz.instance.manager.enable=0 com.biglybt.ui.Main -ui console"

echo "$RUN"

exec $RUN
