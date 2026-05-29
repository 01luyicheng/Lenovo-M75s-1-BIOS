{$擦除} //按“删除”按钮将执行部分
begin
  if not SPIEnterProgMode(_SPI_SPEED_MAX) then LogPrint('Error setting SPI speed');

  BlockSize := 65536; //块大小
  sreg := 0;
  ProgressBar(0, (_IC_SIZE / BlockSize)-1, 0);

  for i:=0 to (_IC_SIZE / BlockSize)-1 do
  begin
    SPIWrite(1, 1, $06); //写入
    SPIWrite(1, 4, $D8, i,0,0); //是

    //繁忙
    repeat
      SPIWrite(0, 1, $05);
      SPIRead(1, 1, sreg);
    until((sreg and 1) <> 1);
    ProgressBar(1);
  end;

  ProgressBar(0, 0, 0);
  SPIExitProgMode();
end
