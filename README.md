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
	\hline 1 \\
	\hline 2 \\
	\hline 3 \\
	\hline 4 \\
	\hline
\end{array}
 =>
\begin{array}{|c|}
    \hline w[n]\\
	\hline 2 \\
	\hline 3 \\
	\hline 4 \\
	\hline 1 \\
	\hline
\end{array}
$$
字节代换:对字节循环的结果通过SBOX进行字节代换。





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




