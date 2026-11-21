#!/system/bin/sh
D=/data/local/tmp/bl
mkdir -p $D
for p in TA aboot alt_aboot s1sbl alt_s1sbl sbl1 alt_sbl1 tz alt_tz hyp alt_hyp rpm alt_rpm pmic alt_pmic sdi alt_sdi keystore devinfo persist apps_log; do
  dd if=/dev/block/bootdevice/by-name/$p of=$D/$p.img 2>/dev/null
done
chmod 644 $D/*.img
ls -l $D
