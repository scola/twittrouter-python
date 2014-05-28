export PYTHONHOME=/data/data/fq.router2/python
export PYTHONPATH=$PYTHONHOME/lib/python2.7/lib-dynload:$PYTHONHOME/lib/python2.7
export PATH=$PYTHONHOME/bin:$PATH
export LD_LIBRARY_PATH=$PYTHONHOME/lib:$LD_LIBRARY_PATH
if [ ! -f $PYTHONHOME/bin/python2 ] ; then
    /data/data/fq.router2/busybox cp $PYTHONHOME/bin/python $PYTHONHOME/bin/python2
fi
$PYTHONHOME/bin/python2 "$@"
