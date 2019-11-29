// gcc-8 -Wall -std=c11 -Os шифр2.c -o шифр2
// gcc-8 -Wall -std=c11 -Os шифр2.c -o шифр2 && ./шифр2
// 2 бита соль
// 2 бита инфа
// итого 4 бита
// таблица шифра личные 2 бита <-- 4 бита шифрованные
// личные данные b00 => могут быть зашифрованы набором 2^2 = 4шт из 
// b0000 ... b1111 2^4 = 16 штук
// разные расклады шифрования для данных
// b00 = ℂ(4,16) = 16*15*14*13/2/3/4 = 1820
// b01 = ℂ(4,12) = 12*11*10*9/2/3/4 = 495
// b10 = ℂ(4,8) = 8*7*6*5/2/3/4 = 70
// b11 = ℂ(4,4) = 4*3*2*1/2/3/4 = 1
// разные расклады шифрования = b00 * b01 * b10 * b11 =
//  = 16*15*14*13/(2*3*4)*12*11*10*9/(2*3*4)*8*7*6*5/(2*3*4)*4*3*2/(2*3*4) = 
//  = 16! / ((4!)^4) = 63063000 = 0x3c243d8
// минимум можно записать с помощью log(2,63063000) = 25.91 бит < 4 байт
// пароль будет 26 бит
// английские буквы 2 * 26 + 10 цифр = 62 знака
// длина буквенного пароля : log ( 62 , 63063000 ) = 4.352 буквы

# include <locale.h>
# include <stdio.h>
# include <stdint.h>
# include <stdlib.h>
# include <time.h>
# include <iso646.h>
# include <stdbool.h>

static  unsigned  long  int fact  ( unsigned  long  int x ) {
  if  ( x ==  0 ) return  0 ;
  unsigned  long  int res = x ;
dowhiletrue :
  --  x ;
  if ( x <= 1UL ) return res ;
  res *=  x ;
  goto dowhiletrue ; }

typedef uint8_t ( * arrp ) [ ] ;
typedef char ( * strp ) [ ] ;
  
static  void  initarr ( arrp  const p , uint8_t const codefree ) {
  uint8_t * i = & ((*p)[0x10]) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ((*p)[0]) ) ; }

static  void  printarr  ( strp const  name , arrp const p , size_t const arrsize ) {
  printf(u8"%s = [ ",*name);
  uint8_t * i = & ((*p)[0]) ;
  do {
    printf("%x , " , (int)( * i )); 
    ++  i ;
  } while ( i not_eq  & ((*p)[arrsize]) ) ;
  fputs(u8"]\n",stdout); }
  
static  void  crypt_decrypt ( arrp const datap , arrp const tablep ,
  arrp const encrp ) {
  uint8_t const * id = &((*datap)[4]) ;
  uint8_t * ied = &((*encrp)[4]) ;
  do {
    -- id ;
    --  ied ;
    ( * ied ) = ( * tablep ) [ * id ] ;
  } while ( id not_eq &((*datap)[0]) ) ; }
  
// указатель на массив разной длины
typedef uint8_t ( * type_raspr4_xp  ) [ ] [ 4 ] ;
  
# define  raspr4_16_size  ((uint16_t)1820U)
# define  raspr4_12_size  ((uint16_t)495U)
# define  raspr4_8_size ((uint8_t)70U)

int main(){
  setlocale(LC_ALL,"");
  unsigned long const fact4 = fact(4) ;
  unsigned long const fact42 = fact4 * fact4 ;
  unsigned long const passmax = fact(16)/fact42/fact42 ;
  printf(u8"максимальный пароль !16/((!4)^4) = 0x%lx\n",passmax);
  printf(u8"максимальный рандом = 0x%x\n",(int)RAND_MAX);
# if  RAND_MAX  !=  0x7fffffff
# error RAND_MAX  !=  0x7fffffff
# endif
  // 31 бит
  srand ( time  ( 0 ) ) ;
  uint32_t const password_const  = (  ( long double ) rand  ( ) ) /
    ( ( long double ) RAND_MAX  ) * ( ( long double ) passmax ) ;
  printf(u8"пароль = 0x%x\n",password_const);
  // пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 16, остаются 15! вариантов пароля
  // пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
  // секретных кодов для соли+данных 0x1
  
  // массив размеров разных распределений
  uint16_t  raspr4_s [ 4 ] = { [ 3 ] = raspr4_16_size , [ 2 ] = raspr4_12_size ,
    [ 1 ] = raspr4_8_size , [ 0 ] = 0 } ;  
  
  uint8_t raspr4_16x [ raspr4_16_size ] [ 4 ] ;
          
  uint8_t raspr4_12x [ raspr4_12_size ] [ 4 ] ;

  uint8_t raspr4_8x [ raspr4_8_size ] [ 4 ] ;
                
  // массив указателей на разные распределения
  type_raspr4_xp  raspr4_x  [ 4 ] = { [ 3 ] = & raspr4_16x , [ 2 ] = & raspr4_12x ,
    [ 1 ] = & raspr4_8x , [ 0 ] = (void*)0  } ;
        
  { uint8_t raspri  = 4 ;
    do {
      uint8_t raspri4 = raspri * 4 ;
      --  raspri  ;
      // raspri = 3 , 2 , 1
      // raspri4 = 16 , 12 , 8
      { uint16_t  j = 0 ;
        type_raspr4_xp ap = raspr4_x [ raspri ] ;
        // ap - указатели на разные массивы
        for(uint8_t i0 = 0 ; i0 < (raspri4 - 3)  ; ++  i0 )
          for(uint8_t i1 = i0 + 1 ; i1 < (raspri4 - 2)  ; ++  i1 )
            for(uint8_t i2 = i1 + 1 ; i2 < (raspri4 - 1 ) ; ++  i2 )
              for(uint8_t i3 = i2 + 1 ; i3 < raspri4  ; ++  i3 ) {
                ( * ap ) [ j ] [ 0 ] = i0  ;
                ( * ap ) [ j ] [ 1 ] = i1  ;
                ( * ap ) [ j ] [ 2 ] = i2  ;
                ( * ap ) [ j ] [ 3 ] = i3  ; 
                ++  j ; } }
    } while ( raspri > 1 ) ; }
  
  uint8_t shifr [ 0x10 ] ;
  // 0 .. 3 - варианты секретных кодов для буквы 0
  // 4 .. 7 - варианты секретных кодов для буквы 1
  // 8 .. b - варианты секретных кодов для буквы 2
  // c .. f - варианты секретных кодов для буквы 3
  
  uint8_t deshi [ 0x10 ] ;
  
  // !!!
  // ... перекинуть в отдельную функцию : ( password const , & array , & array )
  
  uint8_t const codefree = 0xff ;
  initarr ( & shifr , codefree )  ;
  initarr ( & deshi , codefree )  ;
  uint32_t password = password_const ;
  uint16_t  cindex4_16  = password  % raspr4_16_size ;
  password  /=  raspr4_16_size  ;
  
  for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
    shifr [ j ] = raspr4_16x [ cindex4_16 ] [ j ] ;
    deshi [ raspr4_16x [ cindex4_16 ] [ j ] ] = 0 ; }
  
      printf(u8"shifr [ 0 ] = 0x%x , shifr [ 1 ] = 0x%x , shifr [ 2 ] = 0x%x , shifr [ 3 ] = 0x%x\n",(unsigned int)shifr [ 0 ],(unsigned int)shifr [ 1 ],
        (unsigned int)shifr [ 2 ],(unsigned int)shifr [ 3 ]);
      printf ( u8"пароль = %x\n",password);
      
      for ( uint8_t arr_ind = 1 ; arr_ind <= 2 ; ++ arr_ind ) {
        uint8_t index = 0 ;
        uint16_t  cindex4_i  = password  % ( raspr4_s [ 3 - arr_ind ] ) ;
        password  /= ( raspr4_s [ 3 - arr_ind ] ) ;
        { uint8_t old_index = 0xff ;
          for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
            uint8_t new_index = ( * ( raspr4_x [ 3 - arr_ind ] ) )
              [ cindex4_i ] [ j ] ;
            { uint8_t passed = old_index + 1 ;
              do {
                if ( deshi [ index ] == codefree ) {
                  if ( passed == new_index ) break ;
                  ++ passed  ; }
                ++  index ;
              } while ( true ) ; }
            old_index = new_index ;
            shifr [ 0x4 * arr_ind + j ] = index ;
            deshi [ index ] = arr_ind ;
            ++  index ; } }
      
        printf  (
          u8"shifr [ %x ] = 0x%x , shifr [ %x ] = 0x%x , shifr [ %x ] = 0x%x , shifr [ %x ] = 0x%x\n",
          0x4 * arr_ind,(unsigned int)shifr [ 0x4 * arr_ind ],
          0x4 * arr_ind+1,(unsigned int)shifr [ 0x4 * arr_ind+1 ],
          0x4 * arr_ind+2,(unsigned int)shifr [ 0x4 * arr_ind +2 ],
          0x4 * arr_ind+3,(unsigned int)shifr [ 0x4 * arr_ind+3 ] ) ;
        printf ( u8"пароль = %x\n",password); }
      /*
      uint8_t index = 0 ;
      uint16_t  cindex4_12  = password  % ( raspr4_s [ 2 ] ) ;
      password  /= ( raspr4_s [ 2 ] ) ;
      
// !!!
  // ... все циклы собрать компактно
      
      { uint8_t old_index = 0xff ;
        for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
          uint8_t new_index = ( * ( raspr4_x [ 2 ] ) ) [ cindex4_12 ] [ j ] ;
          { uint8_t passed = old_index + 1 ;
            do {
              if ( deshi [ index ] == codefree ) {
                if ( passed == new_index ) break ;
                ++ passed  ; }
              ++  index ;
            } while ( true ) ; }
          old_index = new_index ;
          shifr [ 0x4 + j ] = index ;
          deshi [ index ] = 1 ;
          ++  index ; } }
      
      printf(u8"shifr [ 4 ] = 0x%x , shifr [ 5 ] = 0x%x , shifr [ 6 ] = 0x%x , shifr [ 7 ] = 0x%x\n",(unsigned int)shifr [ 4 ],(unsigned int)shifr [ 5 ],
        (unsigned int)shifr [ 6 ],(unsigned int)shifr [ 7 ]);
      printf ( u8"пароль = %x\n",password);
      index = 0 ;
// беру mod 70 , если пароль очень большой (больше нормы), чтобы получить < 70
      uint16_t  cindex4_8  = password  % ( raspr4_s [ 1 ] ) ;

      { uint8_t old_index = 0xff ;
        for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
          uint8_t new_index = ( * ( raspr4_x [ 1 ] ) ) [ cindex4_8 ] [ j ] ;
          { uint8_t passed = old_index + 1 ;
            do {
              if ( deshi [ index ] == codefree ) {
                if ( passed == new_index ) break ;
                ++ passed  ; }
              ++  index ;
            } while ( true ) ; }
          old_index = new_index ;
          shifr [ 0x8 + j ] = index ;
          deshi [ index ] = 2 ;
          ++  index ; } }
      
      printf(u8"shifr [ 8 ] = 0x%x , shifr [ 9 ] = 0x%x , shifr [ a ] = 0x%x , shifr [ b ] = 0x%x\n",(unsigned int)shifr [ 8 ],(unsigned int)shifr [ 9 ],
        (unsigned int)shifr [ 0xa ],(unsigned int)shifr [ 0xb ]);
*/
      // пароль больше не нужен , беру оставшиеся коды
  
      { uint8_t index3 = 0 ;
        for ( uint8_t  i = 0xc  ; i <=  0xf ; ++  i ) {  
          do  {
            if ( deshi [ index3 ] == codefree ) break  ;
            ++  index3 ;
          } while ( true  ) ; 
          shifr [ i ] = index3 ;
          deshi [ index3 ] = 3 ;
          ++  index3 ; } }

      printf(u8"shifr [ c ] = 0x%x , shifr [ d ] = 0x%x , shifr [ e ] = 0x%x , shifr [ f ] = 0x%x\n",(unsigned int)shifr [ 0xc ],(unsigned int)shifr [ 0xd ],
        (unsigned int)shifr [ 0xe ],(unsigned int)shifr [ 0xf ]);
       
  printarr(&u8"таблица шифровать",&shifr,0x10);
  printarr(&u8"расшифровывать   ",&deshi,0x10);
  uint8_t secretdata [ 4 ] = { 0 , 1 , 2 , 3 } ;
  uint8_t secretdatasole  [ 4 ] ;
  { uint8_t const * id = &(secretdata[4]) ;
    uint8_t * ids = &(secretdatasole[4]) ;
    int ran = rand()  ;
    do {
      -- id ;
      --  ids ;
      // главное данные , хвост - соль : 00 => 0000 или 0001 или 0010 или 0011
      // в таблице всё рядом, 4 варианта равномерно распределены
      (* ids) = ((* id)<<2) bitor (ran%4) ;
      ran >>= 2 ;
    } while ( id not_eq &(secretdata[0]) ) ; }
  printarr(&u8"секретные данные",&secretdata,4);  
  printarr(&u8"с солью         ",&secretdatasole,4);
  uint8_t encrypteddata [ 4 ] ;
  crypt_decrypt ( & secretdatasole , & shifr , & encrypteddata ) ;
  printarr(&u8"зашифрованные данные ",&encrypteddata,4);
  uint8_t decrypteddata [ 4 ] ;
  crypt_decrypt ( & encrypteddata , & deshi , & decrypteddata ) ;
  printarr(&u8"расшифрованные данные",&decrypteddata,4);
  
  puts(u8"Попытаюсь подобрать...");
  uint32_t const password_try = (  ( long double ) rand  ( ) ) /
    ( ( long double ) RAND_MAX  ) * ( ( long double ) passmax ) ;
  printf(u8"попытка , пароль = 0x%x\n",password_try);
  uint8_t decrypteddata_try [ 4 ] = { } ;
  //crypt_decrypt ( & encrypteddata_try , & deshi_try , & decrypteddata_try ) ;
  printarr(&u8"попытка , расшифрованные данные",&decrypteddata_try,4);
}
