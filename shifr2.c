// gcc-8 -Wall -std=c11 -Os shifr2.c -o shifr2
// gcc-8 -Wall -std=c11 -Os shifr2.c -o shifr2 && ./shifr2
// ln -s shifr2 шифр2
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
// ascii буквы 126-32+1 = 95 шт
// длина буквенного пароля : log ( 95 , 63063000 ) = 3.944 буквы

# include <locale.h>
# include <stdio.h>
# include <stdint.h>
# include <stdlib.h>
# include <time.h>
# include <iso646.h>
# include <stdbool.h>
# include <string.h>
# include <errno.h>
# include <termios.h>

//# define  SHIFR_DEBUG

static  unsigned  long  int fact  ( unsigned  long  int x ) {
  if  ( x ==  0 ) return  0 ;
  unsigned  long  int res = x ;
dowhiletrue :
  --  x ;
  if ( x <= 1UL ) return res ;
  res *=  x ;
  goto dowhiletrue ; }

typedef uint8_t ( * arrp ) [ ] ;
typedef uint8_t const ( * arrcp ) [ ] ;
typedef char ( * strp ) [ ] ;
typedef char const ( * strcp ) [ ] ;

// четыре * четыре = шестнадцать
# define  shifr_deshi_size  ((size_t)0x10)

static  void  initarr ( arrp  const p , uint8_t const codefree ) {
  uint8_t * i = & ((*p)[shifr_deshi_size]) ;
  do {
    --  i ;
    ( * i ) = codefree ;
  } while ( i not_eq  & ((*p)[0]) ) ; }

# ifdef SHIFR_DEBUG
static  void  printarr  ( strp const  name , arrp const p , size_t const arrsize ) {
  printf(u8"%s = [ ",*name);
  uint8_t * i = & ((*p)[0]) ;
  do {
    printf("%x , " , (int)( * i )); 
    ++  i ;
  } while ( i not_eq  & ((*p)[arrsize]) ) ;
  fputs(u8"]\n",stdout); }
# endif
  
static  void  crypt_decrypt ( arrp const datap , arrp const tablep ,
  arrp const encrp , size_t const data_size ) {
  uint8_t const * id = &((*datap)[data_size]) ;
  uint8_t * ied = &((*encrp)[data_size]) ;
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

// 0x20 (пробел) ' '    ---     0x7e (тильда) '~'
// 95 шт
# define letters_count ((uint8_t)(0x7eU - 0x20U + 1U))

struct  s_raspr4 {
  
uint8_t x8 [ raspr4_8_size ] [ 4 ] ;
uint8_t x12 [ raspr4_12_size ] [ 4 ] ;
uint8_t x16 [ raspr4_16_size ] [ 4 ] ;

// массив размеров разных распределений
uint16_t  s [ 4 ] ;
  
// массив указателей на разные распределения
type_raspr4_xp  xp  [ 4 ] ;
 
// буквы разрешённые в пароле :
char  letters [ letters_count ] ;

bool  localerus ; 

// хранилище дефолтного состояния
struct termios stored_termios  ;

} ;

static  struct  s_raspr4 raspr4  = { .s = { [ 3 ] = raspr4_16_size , [ 2 ] = raspr4_12_size ,
  [ 1 ] = raspr4_8_size , [ 0 ] = 0 } , .xp = { [ 3 ] = & raspr4.x16 , [ 2 ] = & raspr4.x12 ,
  [ 1 ] = & raspr4.x8 , [ 0 ] = (void*)0  } } ;

static  void  password_to_string ( uint32_t password , strp const string ) {
  char * stringi = & ( ( * string )  [ 0 ] ) ;
  if ( password ) {
    while ( true ) {
      // здесь предыдущие размеры заняли место паролей
      --  password  ;
      ( * stringi ) = raspr4 . letters [ password % (uint32_t)letters_count ] ;
      ++  stringi ;
      if ( password < (uint32_t)letters_count ) break ;
      password /= (uint32_t)letters_count ; } }
  ( * stringi ) = 0 ; }
  
static  bool  isBAD_string_to_password ( strcp const string ,
  uint32_t * const password ) {
  char const * restrict stringi = & ( ( * string )  [ 0 ] ) ;
  if  ( ( * stringi ) == 0 ) {
    ( * password  ) = 0 ;
    return  false ; }
  uint32_t pass = 0 ;
  uint32_t  mult  = 1 ;
  do  {
    uint8_t i = letters_count ;
    do {
      -- i ;
      if ( ( * stringi ) == raspr4 . letters  [ i ] ) goto found ; 
    } while ( i ) ;
    return  true  ;
found :
    pass  +=  ((uint32_t)(i+1)) * mult ;
    mult  *=  (uint32_t)letters_count ;
    ++  stringi ;
  } while ( * stringi ) ;
  ( * password ) = pass ;
  return false ; }
  
static  void  raspr4_init ( void  ) {
  {  char * j = & ( raspr4 . letters [ 0 ] ) ;
    for ( uint8_t i = 0x20 ; i <= 0x7e ; ++ i , ++ j ) ( * j ) = i ; }
    
  uint8_t raspri  = 4 ;
  do {
    uint8_t raspri4 = raspri * 4 ;
    --  raspri  ;
    // raspri = 3 , 2 , 1
    // raspri4 = 16 , 12 , 8
    { uint16_t  j = 0 ;
      type_raspr4_xp ap = raspr4.xp [ raspri ] ;
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
  
// пароль раскладываем в таблицу шифровки , дешифровки
  // пароль % 0x10 = 0xa означает, что 0xa это шифрованный код для соли+данных 0x0
  // пароль делим на 16, остаются 15! вариантов пароля
  // пароль % 0xf = 0xa это порядковый номер для оставшегося НЕ занятого из 0xff
  // секретных кодов для соли+данных 0x1  
void  password_load ( uint32_t  const password_const  , arrp const shifrp , arrp const deship ) {
  
  uint8_t const codefree = 0xff ;
  initarr ( shifrp , codefree )  ;
  initarr ( deship , codefree )  ;
  uint32_t password = password_const ;
  uint16_t  cindex4_16  = password  % raspr4_16_size ;
  password  /=  raspr4_16_size  ;
  
  for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
    (*shifrp) [ j ] = raspr4.x16 [ cindex4_16 ] [ j ] ;
    (*deship) [ raspr4.x16 [ cindex4_16 ] [ j ] ] = 0 ; }
    
      for ( uint8_t arr_ind = 1 ; arr_ind <= 2 ; ++ arr_ind ) {
        uint8_t index = 0 ;
        uint16_t  cindex4_i  = password  % ( raspr4.s [ 3 - arr_ind ] ) ;
        password  /= ( raspr4.s [ 3 - arr_ind ] ) ;
        { uint8_t old_index = 0xff ;
          for ( uint8_t j = 0 ; j < 4 ; ++  j ) {
            uint8_t new_index = ( * ( raspr4.xp [ 3 - arr_ind ] ) )
              [ cindex4_i ] [ j ] ;
            { uint8_t passed = old_index + 1 ;
              do {
                if ( (*deship) [ index ] == codefree ) {
                  if ( passed == new_index ) break ;
                  ++ passed  ; }
                ++  index ;
              } while ( true ) ; }
            old_index = new_index ;
            (*shifrp) [ 0x4 * arr_ind + j ] = index ;
            (*deship) [ index ] = arr_ind ;
            ++  index ; } }
       }
      
      // пароль больше не нужен , беру оставшиеся коды
  
      { uint8_t index3 = 0 ;
        for ( uint8_t  i = 0xc  ; i <=  0xf ; ++  i ) {  
          do  {
            if ( (*deship) [ index3 ] == codefree ) break  ;
            ++  index3 ;
          } while ( true  ) ; 
          (*shifrp) [ i ] = index3 ;
          (*deship) [ index3 ] = 3 ;
          ++  index3 ; } }
  }

# define  alldata_size  12
  
void datasole ( arrcp const secretdata , arrp const secretdatasole , size_t  data_size ) {
  uint8_t const * id = &((*secretdata)[data_size]) ;
  uint8_t * ids = &((*secretdatasole)[data_size]) ;
  int ran = rand()  ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 00 => 0000 или 0001 или 0010 или 0011
    // в таблице всё рядом, 4 варианта равномерно распределены
    (* ids) = ((* id)<<2) bitor (ran%4) ;
    ran >>= 2 ;
  } while ( id not_eq &((*secretdata)[0]) ) ; }  
  
static  void  char_to_hex ( char  buf , char ( * const buf2 ) [ 2 ] ) {
  unsigned  char c = buf & 0xf ;
  if ( c >= 0 and c <= 9 ) (*buf2)[0] = '0' + c ;
  else  (*buf2)[0] = 'a' + (c - 10) ;
  c = (buf >> 4) & 0xf ;
  if ( c >= 0 and c <= 9 ) (*buf2)[1] = '0' + c ;
  else  (*buf2)[1] = 'a' + (c - 10) ; }

static  bool  isBAD_hex_to_char ( char const ( * restrict buf2 ) [ 2 ] , char * const restrict buf ) {
  if  ((*buf2)[0] >= '0' and (*buf2)[0] <= '9') (* buf) = (*buf2)[0] - '0';
  else  if((*buf2)[0] >= 'a' and (*buf2)[0] <= 'f') (* buf) = 10 + ((*buf2)[0] - 'a');
  else  return  true  ;
  if  ((*buf2)[1] >= '0' and (*buf2)[1] <= '9') (* buf) or_eq (((*buf2)[1] - '0')<<4);
  else  if((*buf2)[1] >= 'a' and (*buf2)[1] <= 'f') (* buf) or_eq ((10 + ((*buf2)[1] - 'a'))<<4);
  else  return  true  ;
  return  false ; }

// Отключить эхо-вывод и буферизацию ввода
static  void set_keypress (void) {
    tcgetattr(0, & raspr4.stored_termios);

    struct termios new_termios = raspr4.stored_termios;
        new_termios.c_lflag &= ~(ECHO | ICANON);
        new_termios.c_cc[VMIN] = 1;  
        new_termios.c_cc[VTIME] = 0; 
 
    tcsetattr(0, TCSANOW, & new_termios); }
 
// Восстановление дефолтного состояния
static  void reset_keypress (void) {
    tcsetattr(0, TCSANOW, & raspr4.stored_termios); }  
  
int main  ( int  argc , char * * argv  )  {
  char const * const locale = setlocale(LC_ALL,"") ;
  raspr4  . localerus = ( strcmp  ( locale  , "ru_RU.UTF-8" ) ==  0 ) ;
  bool  flagenc = false ;
  bool  flagdec = false ;
  bool  flagpasswd  = false ;
  bool  flagreadpasswd  = false ;
  bool  flagreadinput = false ;
  bool  flagreadoutput = false ;
  strcp inputfilename = & u8""  ;
  strcp outputfilename  = & u8""  ;
  bool  flaginputfromfile = false ;
  bool  flagoutputfromfile  = false ;
  bool  flagclosefilefrom = false ;
  bool  flagclosefileto = false ;
  bool  flagtext  = false ;
  uint32_t  password_const  ;
  raspr4_init ( ) ;

  # if  RAND_MAX  !=  0x7fffffff
# error RAND_MAX  !=  0x7fffffff
# endif
  // 31 бит
  srand ( time  ( 0 ) ) ;
  
  if  ( argc  <=  1  ) {
    printf  ( raspr4  . localerus ? u8"Локаль = \"%s\"\n" : "Locale = \"%s\"\n" ,
      locale  ) ;
    puts ( raspr4  . localerus ?
      u8"Шифр2\n©2019 Глебов А.Н.\nСинтаксис : shifr2 [параметры]" :
      "Shifr2\n©2019 Glebe A.N.\nSyntax : shifr2 [parameters]" ) ;
    puts  ( raspr4  . localerus ? u8"Параметры :" : "Parameters :"  ) ;
    puts  (raspr4  . localerus ? u8"--ген-пар или\n--gen-psw\tгенерировать пароль" :
      "--gen-psw\tpassword generate" );
    puts  (raspr4  . localerus ? u8"--зашифр или\nencode\tзашифровать" :
      "--encode" );
    puts  (raspr4  . localerus ? u8"--расшифр или\ndecode\tрасшифровать" :
      "--decode" );
    puts  (raspr4  . localerus ? u8"--пароль или\n--passwd \"строка_пароля\"\tиспользовать заданный пароль" :
      "--passwd \"password_string\"\tgiven password using" );
    puts  (u8"--вход \"имя_файла\"\tчитать данные из файла");
    puts  (u8"--выход \"имя_файла\"\tзаписывать данные в файл");
    puts  ( u8"--текст\tшифрованный файл записан текстом ascii");
    return 0 ; }
  
    for ( int argj = 1 ; argv [ argj ] ; ++ argj ) {
      if  ( flagreadpasswd  ) {
        if  ( flagpasswd  ) {
          fputs  (u8"пароль уже задан",stderr);
          return  1 ; }         
        if ( isBAD_string_to_password ( (char(*)[])(argv[argj]) , & password_const ) ) {
          fprintf(stderr,u8"неправильный пароль = \"%s\"",argv[argj]);
          return 1 ; }
        
        char  password_letters [ 6 ] ;
        
        password_to_string ( password_const , & password_letters ) ;
   
// Сделать предупреждение, что пароли равны :
// "$WSh" == "" : 63063000 == 0
        
        if  ( strcmp ( password_letters , argv[argj] ) )  
          printf  ( u8"Предупреждение! Пароль \"%s\" очень большой. Аналогичен = \"%s\"\n"
            ,argv[argj],&(password_letters[0])); 
        
        flagpasswd  = true  ;
        flagreadpasswd = false; }
      else
        if ( flagreadinput ) {
          inputfilename = (char const (*)[])(argv[argj]) ;
          flaginputfromfile = true ;
          flagreadinput = false ; }
        else
         if ( flagreadoutput ) {
          outputfilename = (char const (*)[])(argv[argj]) ;
          flagoutputfromfile = true ;
          flagreadoutput = false ; }
        else 
      if (( strcmp ( argv[argj] , u8"--ген-пар" ) ==  0 ) or
        (strcmp ( argv[argj] , "--gen-psw" ) ==  0)){
        unsigned long const fact4 = fact(4) ;
        unsigned long const fact42 = fact4 * fact4 ;
        unsigned long const passmax = fact(16)/fact42/fact42 ;
        srand ( time  ( 0 ) ) ;
        password_const = (  ( long double ) rand  ( ) ) /
          ( ( long double ) RAND_MAX  ) * ( ( long double ) passmax ) ;
        flagpasswd  = true  ;
        printf(u8"внутренний пароль = %x\n",password_const);
        char  password_letters [ 6 ] ;
        password_to_string ( password_const , & password_letters ) ;
        printf(u8"пароль буквами = \"%s\"\n",&(password_letters[0]));
        { uint32_t password2 ;
          if ( isBAD_string_to_password ( & password_letters , & password2 ) ) {
            fprintf(stderr,u8"неправильный пароль = \"%s\"",& ( password_letters  [ 0 ] ));
            return 1 ; }
          printf  ( u8"из строки во внутренний пароль = %x\n"  , password2 ) ; } }
      else  {
        if (( strcmp ( argv[argj] , u8"--зашифр" ) ==  0 ) or
          ( strcmp ( argv[argj] , "--encode" ) ==  0 ) ) {
          flagenc = true ;
          flagdec = false ; }
        else
        if (( strcmp ( argv[argj] , u8"--расшифр" ) ==  0 )or
          ( strcmp ( argv[argj] , "--decode" ) ==  0 )) { 
          flagdec = true ;
          flagenc = false ; }
        else
        if (( strcmp ( argv[argj] , u8"--пароль" ) ==  0 )or
          ( strcmp ( argv[argj] , "--passwd" ) ==  0 )) { 
          flagreadpasswd  = true  ; }
        else
        if ( strcmp ( argv[argj] , u8"--вход" ) ==  0 ) { 
          flagreadinput  = true  ; }
        else
        if ( strcmp ( argv[argj] , u8"--выход" ) ==  0 ) { 
          flagreadoutput  = true  ; }  
        else
        if ( strcmp ( argv[argj] , u8"--текст" ) ==  0 ) { 
          flagtext = true  ; }  

    }
    }
  
  if(not( flagenc xor flagdec)){
     fputs(u8"не определено : зашифровывать или расшифровывать ?\n",stderr);
     return 1 ; }
     
  if ( not flagpasswd )    {
    char p [ 8 ] ;
    fputs(u8"введите пароль = ",stdout);
    set_keypress  ( ) ;
    char ( * res ) [ 8 ] = ( char ( * ) [ 8 ] ) fgets ( & ( p [ 0 ] ) , 8 , stdin ) ;
    reset_keypress ( ) ;
    char * j = &((*res)[0]) ;
    while ( ( ( * j ) not_eq '\n' ) and ( ( * j ) not_eq 0 ) and ( j < ( & ( * res ) [ 8 ] ) ) ) ++ j ;
    if ( j < ( & ( ( * res ) [ 8 ] ) ) ) ( * j ) = 0 ;
    else  {
      fputs(u8"в пароле нет конца строки\n",stderr);
      return 1 ; }
    if ( res ) {
      //printf ( u8"пароль = \"%s\"\n" , &((*res)[0]) ) ;
      if ( isBAD_string_to_password ( res , & password_const ) ) {
        fprintf ( stderr , u8"неправильный пароль = \"%s\"" , &((*res)[0]) ) ;
        return 1 ; } } }
        
  FILE  * filefrom  = stdin ;
  FILE  * fileto  = stdout  ;
  if ( flaginputfromfile ) {
    FILE * f = fopen(&((*inputfilename)[0]),&("r"[0]));
    if(f == NULL) {
      int e = errno ; 
      fprintf(stderr,u8"Ошибка чтения файла \"%s\" : %s\n",&((*inputfilename)[0]),strerror(e));
      return 1 ;  }
    flagclosefilefrom = true ;
    filefrom = f ; }
  if ( flagoutputfromfile ) {
    FILE * f = fopen(&((*outputfilename)[0]),&("w"[0]));
    if(f == NULL) {
      int e = errno ; 
      fprintf(stderr,u8"Ошибка записи файла \"%s\" : %s\n",&((*outputfilename)[0]),strerror(e));
      return 1 ;  }
    flagclosefileto = true ;
    fileto  = f ; }
  {uint8_t shifr [ shifr_deshi_size ] ;
  // 0 .. 3 - варианты секретных кодов для буквы 0
  // 4 .. 7 - варианты секретных кодов для буквы 1
  // 8 .. b - варианты секретных кодов для буквы 2
  // c .. f - варианты секретных кодов для буквы 3
  
  uint8_t deshi [ shifr_deshi_size ] ;
  
  password_load ( password_const  , & shifr , & deshi ) ;
  
  if ( flagenc ) {
    int bytecount = 0 ;
    do {
      char buf ;
      size_t readcount = fread ( & buf , 1 , 1 , filefrom ) ;
      if ( readcount == 0 ) {
        if ( ferror ( filefrom ) ) {
          fputs(u8"ошибка чтения файла\n",stderr); 
          clearerr ( filefrom ) ; }
        break ; }
      uint8_t secretdata [ 4 ] = { [0]  = buf&3 ,[1]=(buf>>2)&3,[2]=(buf>>4)&3,[3]=(buf>>6)&3} ;
      
      uint8_t secretdatasole  [ 4 ] ;
      datasole ( & secretdata , & secretdatasole , 4 )  ;
      
      uint8_t encrypteddata [ 4 ] ;
      crypt_decrypt ( & secretdatasole , & shifr , & encrypteddata , 4 ) ;
      
      buf = (encrypteddata [ 0 ] & 0xf) bitor ((encrypteddata [ 1 ] & 0xf) << 4) ;
      size_t writecount ;
      if(flagtext) {
        char buf2[2];
        char_to_hex(buf,&buf2);
        writecount = fwrite ( & buf2 , 2 , 1 , fileto ) ; }
      else
        writecount = fwrite ( & buf , 1 , 1 , fileto ) ;
      if ( writecount == 0 ) {
        if ( ferror ( fileto ) ) {
          fputs(u8"ошибка записи файла\n",stderr ); 
          clearerr ( fileto ) ; }
        break ; }
      buf = (encrypteddata [ 2 ] & 0xf) bitor ((encrypteddata [ 3 ] & 0xf) << 4) ;
      if(flagtext) {
        char buf2[2];
        char_to_hex(buf,&buf2);
        writecount = fwrite ( & buf2 , 2 , 1 , fileto ) ;
        bytecount +=  2 ;
        if ( bytecount == 0x10 )  {
          bytecount = 0 ;
          buf2[0] = '\n' ;
          fwrite ( & (buf2[0]) , 1 , 1 , fileto ) ; }  }
      else
        writecount = fwrite ( & buf , 1 , 1 , fileto ) ;
      if ( writecount == 0 ) {
        if ( ferror ( fileto ) ) {
          fputs(u8"ошибка записи файла\n",stderr ); 
          clearerr ( fileto ) ; }
        break ; }  
        
    } while ( true ) ; 
    if ( flagtext and bytecount ) {
      char buf = '\n' ;
      fwrite ( & buf , 1 , 1 , fileto ) ; }
  }
  else  { // декодируем
    do {
      char buf [ 2 ] ;
      size_t readcount ;
      if  ( flagtext  ) {
        char buf4 [ 4 ] ;
        // читаем четыре буквы '0a1b' -> декодируем в два байта "XY"
        do  {
          readcount = fread ( & (buf4[0]) , 1 , 1 , filefrom ) ;
          if ( readcount == 0 ) {
            if ( ferror ( filefrom ) ) {
              fputs(u8"ошибка чтения файла\n",stderr); 
              clearerr ( filefrom ) ; }
            goto out ; }
        } while (not(( buf4[0] >= '0' and buf4[0] <= '9') or (buf4[0] >= 'a' and buf4[0] <= 'f'))) ;
        
        readcount = fread ( & (buf4[1]) , 1 , 3 , filefrom ) ;
        if ( readcount < 3 ) {
          if ( ferror ( filefrom ) ) {
            fputs(u8"ошибка чтения файла\n",stderr); 
            clearerr ( filefrom ) ; }
          fputs(u8"ошибка hex данных\n",stderr); 
          break ; }
        for ( char const * i = &(buf4[1]); i <= &(buf4[3]) ; ++ i )
          if (not(( (*i) >= '0' and (*i) <= '9') or ((*i) >= 'a' and (*i) <= 'f'))) {
            fputs(u8"ошибка hex данных\n",stderr); 
            goto out ; }
        
        if  ( isBAD_hex_to_char ( ( char const ( * ) [ 2 ] ) ( & buf4 ), & (buf[0])  ) ) {
          fputs(u8"ошибка hex данных\n",stderr);
          break ; }
        if  ( isBAD_hex_to_char ( ( char const ( * ) [ 2 ] ) ( & ( buf4 [ 2 ] ) ) , & (buf[1])  ) ) {
          fputs(u8"ошибка hex данных\n",stderr);
          break ; }  
        //printf(u8"[%x %x]",(unsigned char )(buf[0]),(unsigned char )(buf[1]));
        }
      else readcount = fread ( & (buf[0]) , 1 , 2 , filefrom ) ;
      if ( readcount < 2 ) {
        if ( ferror ( filefrom ) ) {
          fputs(u8"ошибка чтения файла\n",stderr); 
          clearerr ( filefrom ) ; }
        break ; }
      uint8_t secretdata [ 4 ] = { [0]  = buf[0]&0xf ,[1]=(buf[0]>>4)&0xf ,
        [2]  = buf[1]&0xf ,[3]=(buf[1]>>4)&0xf      } ;
      uint8_t decrypteddata [ 4 ] ;
      crypt_decrypt ( & secretdata , & deshi , & decrypteddata , 4 ) ;
      
      buf[0] = (decrypteddata [ 0 ] & 0x3) bitor ((decrypteddata [ 1 ] & 0x3) << 2)
        bitor ((decrypteddata [ 2 ] & 0x3)<<4) bitor ((decrypteddata [ 3 ] & 0x3) << 6);
      size_t writecount = fwrite ( & (buf[0]) , 1 , 1 , fileto ) ;
      if ( writecount == 0 ) {
        if ( ferror ( fileto ) ) {
          fputs(u8"ошибка записи файла\n",stderr ); 
          clearerr ( fileto ) ; }
        break ; }
        
    } while ( true ) ;
    
  }
   
  } // shifr deshi
out : ;  
  int resulterror  = 0 ;
  if ( flagclosefileto  ) {
    if  ( fclose  ( fileto  ) ) {
      int e = errno ; 
      fprintf  (stderr, u8"Ошибка закрытия файла записи \"%s\" : %s\n"  , &((*inputfilename)[0]),strerror(e));
      resulterror = 1 ; } }
  if ( flagclosefilefrom ) {
    if  ( fclose  ( filefrom ) ) {
      int e = errno ; 
      fprintf(stderr,u8"Ошибка закрытия файла чтения \"%s\" : %s\n",&((*inputfilename)[0]),strerror(e));
      resulterror = 2 ; } }
  return  resulterror ; 
  
}
