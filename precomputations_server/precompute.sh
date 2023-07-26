C0=$1
C1=$2
FILENAME=$3
SAGE=$4

res=`sage -c "C0=$C0; C1=$C1; FILE_NAME=\"$FILENAME\"; load(\"$SAGE\")"`

echo "Completed"