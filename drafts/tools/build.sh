#!/bin/bash
# Build one draft from its sources under drafts/: the generator twice (byte-equal, and equal to the checked-in
# file), the own checker, build_draft twice, kramdown-rfc twice, the conversion to RFCXML version 3 (xml2rfc --v2v3)
# twice, xml2rfc twice, each pair compared byte for byte; lines over 72 characters; idnits if IDNITS names it (it
# needs network). kramdown-rfc 1.7.43 writes list, spanx and texttable even in v3 mode; the submitted XML is the
# converted one, which has version="3" and none of them; v3_submission.py then takes out the <?line?> marks and
# submissionType and wraps the BCP 14 keywords in <bcp14>, without changing the rendered text. The document date is
# set at build time:
# DOC_DATE for kramdown-rfc (through fixdate.rb) and for xml2rfc (--date). Every exit code is the step's own.
# usage: build.sh <ser|map|id> <DOC_DATE YYYY-MM-DD> <output dir>
# environment: PYTHON (default python3), IDNITS (path of idnits 3; unset: idnits is skipped)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
DRAFTS=$(cd "$HERE/.." && pwd)
W=$1; DOC_DATE=$2; B=$3; mkdir -p "$B"; B=$(cd "$B" && pwd)
PY=${PYTHON:-python3}
export ID_DATE=$DOC_DATE   # the name fixdate.rb reads
case $W in
  ser) N=draft-gruszka-signed-evaluation-receipts-02 ;;
  map) N=draft-gruszka-evaluation-receipt-mappings-03 ;;
  id)  N=draft-gruszka-scitt-statement-identification-02 ;;
  *) echo "unknown draft $W"; exit 2 ;;
esac
Z=$DRAFTS/$W
echo "== draft $W ($N), DOC_DATE $DOC_DATE, $(date -u +%FT%TZ)"
cd "$Z" || exit 2
case $W in
  ser)
    for i in 1 2; do (cd examples && $PY generate_receipts.py "$B/vectors_run$i.json" > /dev/null 2>&1); echo "generate_$i exit=$?"; done
    cmp "$B/vectors_run1.json" "$B/vectors_run2.json"; echo "cmp_generator_runs_exit=$?"
    cmp "$B/vectors_run1.json" examples/vectors.json; echo "cmp_generator_vs_vectors_json_exit=$?"
    (cd examples && $PY check_receipts.py > "$B/check_receipts_run.txt" 2>&1); echo "check_receipts exit=$?"; tail -1 "$B/check_receipts_run.txt" ;;
  map)
    for i in 1 2; do (cd examples && $PY generate_mappings.py "$B/mappings_run$i.json" > "$B/generate_run$i.out" 2>&1); echo "generate_$i exit=$?"; done
    cmp "$B/mappings_run1.json" "$B/mappings_run2.json"; echo "cmp_generator_runs_exit=$?"
    cmp "$B/mappings_run1.json" examples/mappings.json; echo "cmp_generator_vs_mappings_json_exit=$?"
    (cd examples && $PY check_mappings.py mappings.json > "$B/check_mappings_run.txt" 2>&1); echo "check_mappings exit=$?"; tail -1 "$B/check_mappings_run.txt" ;;
  id)
    for i in 1 2; do (cd examples && $PY statement_id_cases.py "$B/cases_run$i.json" > "$B/generate_run$i.out" 2>&1); echo "generate_$i exit=$?"; done
    cmp "$B/cases_run1.json" "$B/cases_run2.json"; echo "cmp_generator_runs_exit=$?"
    cmp "$B/cases_run1.json" examples/cases.json; echo "cmp_generator_vs_cases_json_exit=$?" ;;
esac
for i in 1 2; do (cd draft && $PY build_draft.py > "$B/build_run$i.out" 2>&1); echo "build_draft_$i exit=$?"; cp draft/$N.md "$B/md_run$i.md"; done
cmp "$B/md_run1.md" "$B/md_run2.md"; echo "cmp_md_runs_exit=$?"
echo "== kramdown-rfc $(kramdown-rfc --version 2>&1 | head -1)"
for i in 1 2; do (cd draft && RUBYOPT="-r$HERE/fixdate.rb" kramdown-rfc $N.md > $N.kd.xml 2> kramdown.err); echo "kramdown_$i exit=$?"; cp draft/$N.kd.xml "$B/kdxml_run$i.xml"; done
cmp "$B/kdxml_run1.xml" "$B/kdxml_run2.xml"; echo "cmp_kramdown_xml_runs_exit=$?"
for i in 1 2; do (cd draft && rm -f $N.xml && xml2rfc --v2v3 $N.kd.xml --out $N.xml > v2v3.out 2> v2v3.err); echo "v2v3_$i exit=$?"
  (cd draft && $PY "$HERE/v3_submission.py" $N.xml > v3sub.out 2>&1); echo "v3_submission_$i exit=$?"; cp draft/$N.xml "$B/xml_run$i.xml"; done
cmp "$B/xml_run1.xml" "$B/xml_run2.xml"; echo "cmp_xml_runs_exit=$?"
grep -m1 -o '<rfc [^>]*version="[0-9]*"' draft/$N.xml | grep -o 'version="[0-9]*"' | sed 's/^/xml /'
echo "v2_elements_in_xml (list, spanx, texttable): $(grep -c '<list[ >]\|<spanx[ >]\|<texttable[ >]' draft/$N.xml)"
echo "v2v3_stderr_lines=$(grep -vc 'Created file' draft/v2v3.err)"
echo "v3_submission: $(cat draft/v3sub.out)"
echo "in xml: line PIs $(grep -c '<?line ' draft/$N.xml), submissionType $(grep -c 'submissionType=' draft/$N.xml), bcp14 $(grep -o '<bcp14>' draft/$N.xml | wc -l)"
grep -m1 -o '<date year="[0-9]*" month="[A-Za-z]*" day="[0-9]*"/>' draft/$N.xml
echo "kramdown_stderr_other_lines=$(grep -vc 'explicit settings completely override' draft/kramdown.err)"
echo "== xml2rfc $(xml2rfc --version 2>&1 | head -1)"
for i in 1 2; do (cd draft && xml2rfc --date "$DOC_DATE" --text --html $N.xml 2> xml2rfc.err > xml2rfc.out); echo "xml2rfc_$i exit=$?"; cp draft/$N.txt "$B/txt_run$i.txt"; cp draft/$N.html "$B/html_run$i.html"; done
cmp "$B/txt_run1.txt" "$B/txt_run2.txt"; echo "cmp_txt_runs_exit=$?"
cmp "$B/html_run1.html" "$B/html_run2.html"; echo "cmp_html_runs_exit=$?"
echo "xml2rfc_stderr_lines=$(wc -l < draft/xml2rfc.err)"; sed "s#$Z/##g" draft/xml2rfc.err | head -5
echo "== lines over 72 characters: $(LC_ALL=C.UTF-8 awk 'length($0) > 72' draft/$N.txt | wc -l)"
sed -n 1,10p draft/$N.txt | grep -E "Intended status|Expires|20[0-9][0-9]$"
if [ -n "${IDNITS:-}" ]; then
  echo "== idnits $("$IDNITS" --version 2>&1 | head -1)"
  (cd draft && "$IDNITS" $N.txt > idnits.out 2> idnits.err); echo "idnits_txt exit=$?"
  (cd draft && "$IDNITS" $N.xml > idnits_xml.out 2> idnits_xml.err); echo "idnits_xml exit=$?"
  sed -i "s#$Z#<$W>#g" draft/idnits.out draft/idnits_xml.out
  cp draft/idnits.out draft/idnits.err draft/idnits_xml.out draft/idnits_xml.err "$B/"
  for f in idnits.out idnits_xml.out; do echo "$f: $(grep -o 'Review the .*' draft/$f | head -1)"; grep -E "^ *[0-9]+  [A-Z_0-9]+$" draft/$f; done
  rm -f draft/idnits_xml.out draft/idnits_xml.err
else
  echo "== idnits skipped (IDNITS unset)"
fi
cp draft/$N.md draft/$N.kd.xml draft/$N.xml draft/$N.txt draft/$N.html "$B/"
echo "== sha256"
sha256sum draft/draft_body.md draft/$N.md draft/$N.xml draft/$N.txt draft/$N.html | sed "s#$Z/##"
