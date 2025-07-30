# AES加密解密流程

## 一、准备阶段
### 密钥扩展
密钥扩展用于生成轮密钥，在AES128中，共有十轮需要使用到轮密钥。

最开始有一个4 * 4 = 16字节的密钥矩阵，扩展十次再加上原始的密钥矩阵总共：16 * 10 + 16 = 176字节。这里用w[n]（n从0开始）表示密钥的某一列，由于需要使用原来密钥来进行扩展。

$$
\begin{array}{|c|c|c|c|c|}
    \hline w[0] & w[1] & w[2] & w[3] & w[4] \\
	\hline 1 & 5 & 9 & c & \\
	\hline 2 & 6 & 0 & d &\\
	\hline 3 & 7 & a & e &\\
	\hline 4 & 8 & b & f &\\
	\hline
\end{array}
$$

1. 当n不为4的倍数时，则第n列为: w[n] = w[n-4]⊕w[n-1]。
2. 当n为4的倍数时，则第n列为: w[n] = w[n-4]⊕T(w[n-1])。

这里再讲述T(w[n-1])怎么计算：

函数T由三部分组成：字循环、字节代换和轮常量异或。

字循环：将第n列的四个字节循环左移一个字节，如下：

$$
\begin{array}{|c|}
    \hline w[n]\\
	\hline c \\
	\hline d \\
	\hline e \\
	\hline f \\
	\hline
\end{array}
 =>
\begin{array}{|c|}
    \hline w[n]\\
	\hline d \\
	\hline e \\
	\hline f \\
	\hline c \\
	\hline
\end{array}
$$

字节代换:对字节循环的结果通过SBOX进行字节代换。例如该字节如果为0x12，则找到[`Sbox表`](#sbox表)中的第1行第2列中的字节0xc9进行替换，实际编程时通过sbox[0x12]进行获取。

$$
\begin{array}{|c|}
    \hline w[n]\\
	\hline d \\
	\hline e \\
	\hline f \\
	\hline c \\
	\hline
\end{array}
 =>
\begin{array}{|c|}
    \hline w[n]\\
	\hline d7 \\
	\hline ab \\
	\hline 76 \\
	\hline fe \\
	\hline
\end{array}
$$

轮常量异或：将字节代换后的结果与轮常量进行异或。如果是第1轮的密钥扩展，则使用第1列的Rcon中的轮常量。

$$
\begin{array}{|c|}
    \hline w[n]\\
	\hline d7 \\
	\hline ab \\
	\hline 76 \\
	\hline fe \\
	\hline \\
\end{array}
⊕
\begin{array}{|c|}
    \hline w[n]\\
	\hline 01 \\
	\hline 00 \\
	\hline 00 \\
	\hline 00 \\
	\hline \\
\end{array}
$$

## 二、加密步骤
### 1. 初始变换
将原始密文和第0轮的密钥(即原始密钥，第1轮密钥为扩展后的密钥)进行异或。
### 2. 9轮循环运算
9轮循环运算包括
#### (1) 字节代换(SubBytes)
使用[`Sbox表`](#sbox表)进行字节代换、行移位、列混合、轮密钥加，需要依次进行。
#### (2) 行移位(ShiftRows)
第1行保持不变，第2行左移1个字节，第3行左移2个字节，第3行左移3个字节。

$$
\begin{array}{|c|c|c|c|}
	\hline 1 & 5 & 9 & c \\
	\hline 2 & 6 & 0 & d \\
	\hline 3 & 7 & a & e \\
	\hline 4 & 8 & b & f \\
	\hline \\
\end{array}
=>
\begin{array}{|c|c|c|c|}
	\hline 1 & 5 & 9 & c \\
	\hline 6 & 0 & d & 2 \\
	\hline a & e & 3 & 7 \\ 
	\hline f & 4 & 8 & b \\
	\hline \\
\end{array}
$$





#### (3) 列混合(MixColumns)
将矩阵左乘一个Mix矩阵。
在这里的左乘和矩阵运算有区别。
- 如果左乘0x01，则不变
- 如果左乘0x02，如果最高位为0，则左移一位，最高位为1，则左移一位并与0x1b进行异或。
- 如果左乘0x03，则相当于左乘0x02再与其进行异或。


$$
\begin{bmatrix}
S'_{0,0} & S'_{0,1} & S'_{0,2} & S'_{0,3} \\
S'_{1,0} & S'_{1,1} & S'_{1,2} & S'_{1,3} \\
S'_{2,0} & S'_{2,1} & S'_{2,2} & S'_{2,3} \\
S'_{3,0} & S'_{3,1} & S'_{3,2} & S'_{3,3} \\
\end{bmatrix}

=

\begin{bmatrix}
02 & 03 & 01 & 01 \\
01 & 02 & 03 & 01 \\
01 & 01 & 02 & 03 \\
03 & 01 & 01 & 02 \\
\end{bmatrix}

\begin{bmatrix}
S_{0,0} & S_{0,1} & S_{0,2} & S_{0,3} \\
S_{1,0} & S_{1,1} & S_{1,2} & S_{1,3} \\
S_{2,0} & S_{2,1} & S_{2,2} & S_{2,3} \\
S_{3,0} & S_{3,1} & S_{3,2} & S_{3,3} \\
\end{bmatrix}

$$

$$
S'_{0,j}=(2 * S_{0,j})⊕(3 * S_{1,j})⊕S_{2,j}⊕S_{3,j} \\
S'_{1,j}=S_{0,j}⊕(2 * S_{1,j})⊕(3 * S_{2,j})⊕S_{3,j} \\
S'_{2,j}=S_{0,j}⊕S_{1,j}⊕(2 * S_{2,j})⊕(3 * S_{3,j}) \\
S'_{3,j}=(3 * S_{0,j})⊕S_{1,j}⊕S_{2,j}⊕(2 * S_{3,j}) \\
$$

#### (4) 轮密钥加(AddRoundKey)
将列混合得到的矩阵和轮密钥进行异或
### 3. 1轮最终轮运算
与9轮循环运算少了一个列混合，其余步骤相同:relaxed:。
### 4. 得到密文
最终得到了密文:smiley:


## 附录
### SBOX表


$$
\begin{array}{|c|c|c|c|c|c|c|c|c|c|c|c|c|c|c|c|c|}
\hline &0&1&2&3&4&5&6&7&8&9&10&11&12&13&14&15\\
\hline 0&63&7c&77&7b&f2&6b&6f&c5&30&01&67&2b&fe&d7&ab&76\\
\hline 1&ca&82&c9&7d&fa&59&47&f0&ad&d4&a2&af&9c&a4&72&c0\\
\hline 2&b7&fd&93&26&36&3f&f7&cc&34&a5&e5&f1&71&d8&31&15\\
\hline 3&04&c7&23&c3&18&96&05&9a&07&12&80&e2&eb&27&b2&75\\
\hline 4&09&83&2c&1a&1b&6e&5a&a0&52&3b&d6&b3&29&e3&2f&84\\
\hline 5&53&d1&00&ed&20&fc&b1&5b&6a&cb&be&39&4a&4c&58&cf\\
\hline 6&d0&ef&aa&fb&43&4d&33&85&45&f9&02&7f&50&3c&9f&a8\\
\hline 7&51&a3&40&8f&92&9d&38&f5&bc&b6&da&21&10&ff&f3&d2\\
\hline 8&cd&0c&13&ec&5f&97&44&17&c4&a7&7e&3d&64&5d&19&73\\
\hline 9&60&81&4f&dc&22&2a&90&88&46&ee&b8&14&de&5e&0b&db\\
\hline 10&e0&32&3a&0a&49&06&24&5c&c2&d3&ac&62&91&95&e4&79\\
\hline 11&e7&c8&37&6d&8d&d5&4e&a9&6c&56&f4&ea&65&7a&ae&08\\
\hline 12&ba&78&25&2e&1c&a6&b4&c6&e8&dd&74&1f&4b&bd&8b&8a\\
\hline 13&70&3e&b5&66&48&03&f6&0e&61&35&57&b9&86&c1&1d&9e\\
\hline 14&e1&f8&98&11&69&d9&8e&94&9b&1e&87&e9&ce&55&28&df\\
\hline 15&8c&a1&89&0d&bf&e6&42&68&41&99&2d&0f&b0&54&bb&16 \\ 
\hline
\end{array}
$$

### Rcon表(轮常量表)

$$
\begin{array}{|c|c|c|c|c|c|c|c|c|c|}
	\hline 01 & 02 & 04 & 08 & 10 & 20 & 40 & 80 & 1b & 36 \\
	\hline 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 \\
	\hline 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 \\
	\hline 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 & 00 \\
	\hline
\end{array}
$$

### Mix表(列混合表)

$$
\begin{array}{|c|c|c|c|}
\hline 02 & 03 & 01 & 01 \\
\hline 01 & 02 & 03 & 01 \\
\hline 01 & 01 & 02 & 03 \\
\hline 03 & 01 & 01 & 02 \\
\hline
\end{array}
$$

