RESULT_USERNAME="false"
if [[ $OUTPUT == *"$JUPYTERHUB_USER"* ]]; then
  echo "JUPYTERHUB_USER there: $JUPYTERHUB_USER"
  RESULT_USERNAME="true"
else
  echo "JUPYTERHUB_USER missing: $JUPYTERHUB_USER"
  exit 1
fi
echo $RESULT_USERNAME

### Check for BASE_URL:
RESULT_BASE_URL="false"
if [ -z ${BASE_URL+x} ]; then
  echo "No BASE_URL set, omitting this check."
  RESULT_BASE_URL="true"
elif [[ $OUTPUT == *"$BASE_URL"* ]]; then
  echo "BASE_URL there: $BASE_URL"
  RESULT_BASE_URL="true"
else
  echo "BASE_URL missing: $BASE_URL"
  exit 1
fi
echo $RESULT_BASE_URL

### Check the exit code
RESULT_EXITCODE=-99
jupyter notebook list
RESULT_EXITCODE=$?
echo "Exit code: $RESULT_EXITCODE"

exit $RESULT_EXITCODE



