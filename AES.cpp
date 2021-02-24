#include "AES.h"
// 参考https://blog.csdn.net/qq_28205153/article/details/55798628#t12

// AES分组长度只能是128位，也就是说，每个分组为16个字节（每个字节8位）。密钥的长度可以使用128位、192位或256位。
AES::AES(int keyLen)
{
  this->Nb = 4;
  switch (keyLen)
  {
  case 128:
    this->Nk = 4;
    this->Nr = 10;
    break;
  case 192:
    this->Nk = 6;
    this->Nr = 12;
    break;
  case 256:
    this->Nk = 8;
    this->Nr = 14;    break;
  default:
    throw "Incorrect key length";
  }

  blockBytesLen = 4 * this->Nb * sizeof(unsigned char); // AES只能用128位的块，也就是16字节
}


/**
 * @brief   ECB mode
 * @param  in               输入文本
 * @param  inLen            输入文本长度
 * @param  key              My Param doc
 * @param  outLen           My Param doc
 * @return unsigned char* 
 */
unsigned char *AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned int &outLen)
{

  outLen = GetPaddingLength(inLen); // 设置输入长度Padding，为16byte的倍数
  unsigned char *alignIn = PaddingNulls(in, inLen, outLen); // 对输入进行补全
  unsigned char *out = new unsigned char[outLen]; // 输出结果
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];  // 轮密钥
  KeyExpansion(key, roundKeys); //密钥扩展


  for (unsigned int i = 0; i < outLen; i += blockBytesLen)  // 分块加密，加密以16字节为一组
  {
    EncryptBlock(alignIn + i, out + i, roundKeys);
  }

  delete[] alignIn;
  delete[] roundKeys;

  return out;
}

unsigned char *AES::DecryptECB(unsigned char in[], unsigned int inLen, unsigned char key[])
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);

  for (unsigned int i = 0; i < inLen; i += blockBytesLen)
  {
    DecryptBlock(in + i, out + i, roundKeys);
  }

  delete[] roundKeys;

  return out;
}

/**
 * @brief CBC mode
 * @param  in               My Param doc
 * @param  inLen            My Param doc
 * @param  key              My Param doc
 * @param  iv               My Param doc
 * @param  outLen           My Param doc
 * @return unsigned char* 
 */
unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char *iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];      // 分块
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];


  KeyExpansion(key, roundKeys);   // 密钥扩展

  memcpy(block, iv, blockBytesLen);   // 将iv按照blockByteLen长度拷贝到block中
  for (unsigned int i = 0; i < outLen; i += blockBytesLen)
  {
      //  cbc模式是先将明文切分成若干小段，然后每一小段与初始块或者上一段的密文段进行异或运算后，再与密钥进行加密。
    XorBlocks(block, alignIn + i, block, blockBytesLen);  // 注意alignIn + i是明文指针， alignIn + i表示起始位置，blockBytesLen限制范围

    EncryptBlock(block, out + i, roundKeys);
    memcpy(block, out + i, blockBytesLen);    // 密文放入block
  }

  delete[] block;
  delete[] alignIn;
  delete[] roundKeys;

  return out;
}


unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char *iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i += blockBytesLen)
  {
    DecryptBlock(in + i, out + i, roundKeys);
    XorBlocks(block, out + i, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }

  delete[] block;
  delete[] roundKeys;

  return out;
}

/**
 * @brief   CFB mode
 * @param  in               My Param doc
 * @param  inLen            My Param doc
 * @param  key              My Param doc
 * @param  iv               My Param doc
 * @return unsigned char* 
 */
unsigned char *AES::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);    // 输入补全
  unsigned char *out = new unsigned char[outLen];

  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, roundKeys);   // 块加密，输出encrptedBlocl
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);   // 明文与密文块encryptedBlock异或，得到输出。
    memcpy(block, out + i, blockBytesLen);    // 输出作为下一轮的加密输入，注意到明文直接参与异或运算，异或结果进行加密
  }
  
  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;
  delete[] roundKeys;

  return out;
}


unsigned char *AES::DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, roundKeys);
    XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] encryptedBlock;
  delete[] roundKeys;

  return out;
}

/**
 * @brief   对明文padding，使长度成为16字节的倍数
 * @param  in               My Param doc
 * @param  inLen            My Param doc
 * @param  alignLen         My Param doc
 * @return unsigned char* 
 */
unsigned char *AES::PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen)
{
  unsigned char *alignIn = new unsigned char[alignLen];
  memcpy(alignIn, in, inLen); // 将in内容copy到alignIn中
  memset(alignIn + inLen, 0x00, alignLen - inLen); // 对alignIn，从inLen到alignLen， 用0赋值
  return alignIn;
}

unsigned int AES::GetPaddingLength(unsigned int len)
{
  unsigned int lengthWithPadding = (len / blockBytesLen);
  if (len % blockBytesLen)
  {
    lengthWithPadding++;
  }

  lengthWithPadding *= blockBytesLen;

  return lengthWithPadding;
}


/**
 * @brief  块加密方法
 * @param  in               输入明文
 * @param  out              加密后密文
 * @param  roundKeys        轮密钥
 */
void AES::EncryptBlock(unsigned char in[], unsigned char out[], unsigned char *roundKeys)
{
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned char[4 * Nb];   // state是一个4*16的矩阵
  int i, j, round;
  for (i = 0; i < 4; i++)
  {
    state[i] = state[0] + Nb * i; // 初始化state[0~3]
  }

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = in[i + 4 * j];    // 将16字节的in数组转为4*4矩阵state, 按照列顺序
    }
  }

  AddRoundKey(state, roundKeys);  // 轮密钥加，明文与原始密钥异或。就轮密钥加步骤用到了密钥

  // 四个子步骤
  for (round = 1; round <= Nr - 1; round++)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb);   // roundKeys是指针
  }

  // 最后一轮，没有列混淆
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, roundKeys + Nr * 4 * Nb);

  // state解码为out
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
}

void AES::DecryptBlock(unsigned char in[], unsigned char out[], unsigned char *roundKeys)
{
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned char[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++)
  {
    state[i] = state[0] + Nb * i;
  }

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys + Nr * 4 * Nb);

  for (round = Nr - 1; round >= 1; round--)
  {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb); 
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, roundKeys);

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
}

/**
 * @brief   四个加密子步骤
 * @param  state            My Param doc
 */
// 字节代换，利用sbox
void AES::SubBytes(unsigned char **state)
{
  int i, j;
  unsigned char t;
  // 输入为16个字节，每个字节进行一次代换，一共进行16次
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = sbox[t / 16][t % 16];   // t为一个字节，或者说一个0～255的数，t/16作为行索引，t%16作为列索引，从sbox中查找
    }
  }
}

/**
 * @brief   行移位
 * @param  state            状态矩阵，4*4矩阵，代表16字节的输入
 * @param  i                行索引
 * @param  n                移动大小
 */
void AES::ShiftRow(unsigned char **state, int i, int n) // shift row i on n positions
{
  unsigned char *tmp = new unsigned char[Nb];
  for (int j = 0; j < Nb; j++)
  {
    tmp[j] = state[i][(j + n) % Nb];
  }
  memcpy(state[i], tmp, Nb * sizeof(unsigned char));

  delete[] tmp;
}

// 行移位
void AES::ShiftRows(unsigned char **state)
{
  ShiftRow(state, 1, 1);    // 状态矩阵，行索引为1,2,3的分别对应移动1,2,3字节
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}



// 列混淆, 对state矩阵列处理
/* Reference https://en.wikipedia.org/wiki/Rijndael_mix_columns#Implementation_example */
void AES::MixSingleColumn(unsigned char *r)
{
  unsigned char a[4];
  unsigned char b[4];
  unsigned char c;
  unsigned char h;
  /* The array 'a' is simply a copy of the input array 'r'
  * The array 'b' is each element of the array 'a' multiplied by 2
  * in Rijndael's Galois field
  * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
  for (c = 0; c < 4; c++)
  {
    a[c] = r[c];
    /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
    h = (unsigned char)((signed char)r[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
    b[c] = r[c] << 1;                            /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
    b[c] ^= 0x1B & h;                            /* Rijndael's Galois field */
  }
  r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
  r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
  r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
  r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

/**
 * @brief   列混淆
 * @param  state            My Param doc
 */
void AES::MixColumns(unsigned char **state)
{
  unsigned char *temp = new unsigned char[4];

  for (int i = 0; i < 4; ++i)
  {
    for (int j = 0; j < 4; ++j)
    {
      temp[j] = state[j][i]; //place the current state column in temp
    }
    MixSingleColumn(temp); //temp代表state的一列，列混淆实际针对state矩阵的某一列进行处理
    for (int j = 0; j < 4; ++j)
    {
      state[j][i] = temp[j]; //when the column is mixed, place it back into the state
    }
  }
  delete[] temp;
}

/**
 * @brief   轮密钥加， state矩阵分别与密钥矩阵w[4i+n]异或
 * @param  state            My Param doc
 * @param  key              My Param doc
 */
void AES::AddRoundKey(unsigned char **state, unsigned char *key)
{
  int i, j;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = state[i][j] ^ key[i + 4 * j];
    }
  }
}


/**
 * @brief  解密四个步骤
 * @param  state            My Param doc
 */
// 逆字节代换， 使用逆sbox
void AES::InvSubBytes(unsigned char **state)
{
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = inv_sbox[t / 16][t % 16];
    }
  }
}

// 字节乘法， 逆列混淆需要用
unsigned char AES::mul_bytes(unsigned char a, unsigned char b) // multiplication a and b in galois field
{
  unsigned char p = 0;
  unsigned char high_bit_mask = 0x80;
  unsigned char high_bit = 0;
  unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

  for (int i = 0; i < 8; i++)
  {
    if (b & 1)
    {
      p ^= a;
    }

    high_bit = a & high_bit_mask;
    a <<= 1;
    if (high_bit)
    {
      a ^= modulo;
    }
    b >>= 1;
  }

  return p;
}

// 逆列混淆
void AES::InvMixColumns(unsigned char **state)
{
  unsigned char s[4], s1[4];
  int i, j;

  for (j = 0; j < Nb; j++)
  {
    for (i = 0; i < 4; i++)
    {
      s[i] = state[i][j];
    }
    s1[0] = mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]);
    s1[1] = mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]);
    s1[2] = mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]);
    s1[3] = mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]);

    for (i = 0; i < 4; i++)
    {
      state[i][j] = s1[i];
    }
  }
}

// 逆行移位
void AES::InvShiftRows(unsigned char **state)
{
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

/**
 * @brief   每一小块明文与初始块或者上一段的密文段进行异或运算,cbc模式特点。
 * @param  a                My Param doc
 * @param  b                My Param doc
 * @param  c                My Param doc
 * @param  len              My Param doc
 */
void AES::XorBlocks(unsigned char *a, unsigned char *b, unsigned char *c, unsigned int len)
{
  for (unsigned int i = 0; i < len; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}



/**
 * @brief   密钥扩展
 * @param  key              My Param doc
 * @param  w                My Param doc
 * 
 * 1. 将4*4矩阵密钥组成W[0~3]
 * 2. 对W数组扩充4×轮数 个新列，例如128bit有10论，则扩充40个新列，构成总共44列的扩展密钥数组。具体步骤如下：
 * 如果i不是4的倍数，那么第i列由如下等式确定：W[i]=W[i-4]^W[i-1]
 * 如果i是4的倍数，那么第i列由如下等式确定：W[i]=W[i-4]^T(W[i-1])
 * 
 * 函数T由3部分组成：字循环、字节代换和轮常量异或，这3部分的作用分别如下。
 * a.字循环：将1个字中的4个字节循环左移1个字节。即将输入字[b0, b1, b2, b3]变换成[b1,b2,b3,b0]。
 * b.字节代换：对字循环的结果使用S盒进行字节代换。
 * c.轮常量异或：将前两步的结果同轮常量Rcon[j]进行异或，其中j表示轮数
 * 
 * 扩展后的密钥长度，根据选择密钥长度得到4*(Nr+1)的密钥数组。
 */
void AES::KeyExpansion(unsigned char key[], unsigned char w[])
{
  unsigned char *temp = new unsigned char[4];
  unsigned char *rcon = new unsigned char[4];

  int i = 0;
  while (i < 4 * Nk)
  {
    w[i] = key[i];
    i++;
  }

  i = 4*Nk; // Nk=4
  while (i <  4*Nb * (Nr + 1))  //4*11
  {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

  // 得到T函数
    if (i / 4 % Nk == 0)  // 如果是Nk的倍数
    {
      RotWord(temp);  // 字循环
      SubWord(temp);  // 字节代换
      Rcon(rcon, i / (Nk * 4));   // 生成轮常量
      XorWords(temp, rcon, temp);  // 轮常量异或
    }
    else if (Nk > 6 && i / 4 % Nk == 4)
    {
      SubWord(temp);
    }

    w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
    i += 4;
  }

  delete[] rcon;
  delete[] temp;
}

// 字循环
void AES::SubWord(unsigned char *a)
{
  int i;
  for (i = 0; i < 4; i++)
  {
    a[i] = sbox[a[i] / 16][a[i] % 16];
  }
}

// 字节代换
void AES::RotWord(unsigned char *a)
{
  unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

// 密钥生成，轮异或
void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c)
{
  int i;
  for (i = 0; i < 4; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

// 生成轮数组
void AES::Rcon(unsigned char *a, int n)
{
  int i;
  unsigned char c = 1;
  for (i = 0; i < n - 1; i++)
  {
    c = xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

unsigned char AES::xtime(unsigned char b) // multiply on x
{
  return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

/**
 * @brief   打印16进制数组
 * @param  a                My Param doc
 * @param  n                My Param doc
 */
void AES::printHexArray(unsigned char a[], unsigned int n)
{
  for (unsigned int i = 0; i < n; i++)
  {
    printf("%02x ", a[i]);
  }
}