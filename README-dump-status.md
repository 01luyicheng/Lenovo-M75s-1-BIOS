# BIOS/固件读取记录

## 火神革命-X99-V202
- 芯片: Winbond W25Q128JVSQ (16MB, 3.3V)
- 文件: `火神革命-X99-V202/x99_bios.bin` (全空 0xFF)
- 状态: ⚠️ 已被擦除（误操作）

## 联想-M75s-1
- 主板型号: ThinkCentre M75s-1A5P
- 芯片1: MX25L8005E (1MB, 3.3V) - 未成功读取
- 芯片2: MX25U12873F (16MB, 1.8V) - 主BIOS

### MX25U12873F 读取状态
- 文件: `联想-M75s-1/BIOS-MX25U12873F-dump-incomplete.bin`
- 大小: 16MB (16,777,216 bytes)
- 状态: ⚠️ 不完整/不可靠
- 原因: 烧录夹接触极不稳定，读取过程中接触断开，后半部分可能为误读
- 数据特征:
  - 包含有效OEM信息: ThinkCentre M75s-1A5P
  - 序列号: 3K7AHKC73M8BX5S36XWPVC
  - 后8MB (MB 8-15) 全部为 0x00，疑为读取错误
  - 需要重新读取验证

## TODO
- [ ] 购买新的烧录夹
- [ ] 重新读取联想M75s-1的MX25U12873F
- [ ] 尝试读取MX25L8005E (1MB芯片用途待确认)
