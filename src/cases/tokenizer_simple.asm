; Config end
page_table equ 0x03
mapping_2m equ 0x83

  movd eax, 0x1000
  movw [eax + 0x000], \
    page_table | 0x2000 ; Write page table root
  movw [0x1FF8], page_table | 0x2000 ; Upper half is same
  movd cr3, eax

  movw bx, 0x2018
  movw ax, 0x6003
morel1map:
  movw [bx], ax
  subb ah, 0x10
  subb bl, 8
  jcc morel1map

  movw [0x2FF0], page_table | 0x3000 ; -2G
  movw [0x2FF8], page_table | 0x4000 ; -1G

  ; Indentity map bottom 2G
  movw di, 0x3000
  xorw ax, ax
moremappings:
  movb [di], mapping_2m ; Third level
  movw [di + 2], ax
  addw di, 8
  addw ax, 32
  jcc moremappings
