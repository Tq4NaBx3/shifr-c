// Шифр ©2020-2 Глебов А.Н.
// Shifr ©2020-2 Glebe A.N.

# include <stdio.h>
# include <sys/types.h> // ssize_t

# ifdef SHIFR_SYSCALL_RANDOM
# include <sys/syscall.h>
# else
# include <sys/random.h>
# endif

# include <iso646.h> // not_eq
# include "define.h"
# include "private.h"
# include "struct.h"
# include "inline-pri.h"

// generate random number [ fr .. to ]
unsigned  int shifr_uirandfrto  ( t_ns_shifr * const ns_shifrp ,
  unsigned  int const fr , unsigned  int const to ) {
# ifdef SHIFR_DEBUG
  if ( fr >= to ) {
    fprintf ( stderr  , "uirandfrto : fr >= to , fr = %u , to = %u\n"  ,
      fr , to ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp ) "uirandfrto : fr >= to" ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
  if ( fr + 0x100 <= to ) {
    fprintf ( stderr  , "uirandfrto : fr + 0x100 <= to , fr = %u , to = %u\n"  ,
      fr , to ) ;
    ns_shifrp  -> string_exception  = ( shifr_strcp )
      "uirandfrto : fr + 0x100 <= to" ;
    longjmp ( ns_shifrp  -> jump  , 1 ) ; }
# endif
  uint8_t buf ;
  do {
# ifdef SHIFR_DEBUG
    ssize_t const r = 
# endif
# ifdef SHIFR_SYSCALL_RANDOM
      syscall ( SYS_getrandom , & buf , 1 , 0 ) ;
# else
      getrandom ( & buf , 1 , 0 ) ;
# endif
# ifdef SHIFR_DEBUG
    if ( r == -1 ) {
      perror  ( "uirandfrto : getrandom" ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "uirandfrto : getrandom" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    if ( r not_eq 1 ) {
      fprintf ( stderr  , "uirandfrto : r = %ld not_eq 1\n"  , r ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp )
        "uirandfrto : r not_eq 1" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
  } while ( buf + 0x100 % ( to - fr + 1 ) >= 0x100 ) ;
  return  fr + buf % ( to - fr + 1 ) ; }

// data_size = 4
void shifr_datasalt2 ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcp const secretdata , shifr_arrp const secretdatasalt ,
  size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasalt  ) [ data_size ] ) ;
  uint8_t ran ;
# ifdef SHIFR_DEBUG
  ssize_t const r =
# endif
# ifdef SHIFR_SYSCALL_RANDOM
    syscall ( SYS_getrandom , & ran , 1 , 0 ) ;
# else
    getrandom ( & ran , 1 , 0 ) ;
# endif
# ifdef SHIFR_DEBUG
    if ( r == -1 ) {
      perror  ( "datasalt2 : getrandom" ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "datasalt2 : getrandom" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    if ( r not_eq 1 ) {
      fprintf ( stderr  , "datasalt2 : r = %ld not_eq 1\n"  , r ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "datasalt2 : r not_eq 1" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 10 =>
    //   10_00 или 10_01 или 10_10 или 10_11
    // в таблице всё рядом, 4 варианта равномерно распределены
    // the main thing is data , the tail is salt : 10 =>
    //   10_00 or 10_01 or 10_10 or 10_11
    // in the table, everything is side by side, 4 options are evenly distributed
    ( * ids ) = ( uint8_t ) (
      ( ( * id  ) <<  2 ) bitor
      ( ran bitand  0x3 ) ) ;
    ran >>= 2 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ; }

// data_size = 1 .. 3
void shifr_datasalt3 ( t_ns_shifr * const ns_shifrp ,
  shifr_arrcp const secretdata , shifr_arrp const secretdatasalt ,
  size_t const data_size ) {
  uint8_t const * restrict  id = &  ( ( * secretdata  ) [ data_size ] ) ;
  uint8_t * restrict  ids = & ( ( * secretdatasalt  ) [ data_size ] ) ;
  int const arans = ( ( data_size == 3 ) ? 2 : 1 ) ;
  uint8_t aran [ arans ] ;
# ifdef SHIFR_DEBUG
  ssize_t const r = 
# ifdef SHIFR_SYSCALL_RANDOM
    syscall ( SYS_getrandom , & ( aran [ 0 ] ) , arans , 0 ) ;
# else
    getrandom ( & ( aran [ 0 ] ) , ( size_t ) arans , 0 ) ;
# endif
    if ( r == -1 ) {
      perror  ( "datasalt3 : getrandom" ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) "datasalt3 : getrandom" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
    if ( r not_eq arans ) {
      fprintf ( stderr  , "datasalt3 : r = %ld not_eq %d\n"  , r , arans ) ;
      ns_shifrp  -> string_exception  = ( shifr_strcp ) 
        "datasalt3 : r not_eq arans" ;
      longjmp ( ns_shifrp  -> jump  , 1 ) ; }
# endif // SHIFR_DEBUG
  unsigned  int ran = ( ( unsigned  int ) ( aran [ 0 ] ) ) ;
  if ( arans == 2 )
    ran |=  ( ( ( unsigned  int ) ( aran [ 1 ] ) ) << 8 ) ;
  do {
    -- id ;
    --  ids ;
    // главное данные , хвост - соль : 101 =>
    //   101_000 или 101_001 или ... или 101_111
    // в таблице всё рядом, 8 вариантов равномерно распределены
    // the main thing is data , the tail is salt : 101 =>
    //   101_000 or 101_001 or ... or 101_111
    // in the table, everything is side by side, 8 options are evenly distributed
    ( * ids ) = ( uint8_t )
      ( ( ( unsigned int ) ( ( * id  ) <<  3 ) ) bitor
      ( ran bitand  0x7 ) ) ;
    ran >>= 3 ;
  } while ( id not_eq & ( ( * secretdata  ) [ 0 ] ) ) ; }
  
// пишу по шесть бит
// secretdatasaltsize - количество шести-битных отделов (2 или 3)
// encrypteddata - массив шести-битных чисел
// I write in six bits
// secretdatasaltsize - the number of six-bit divisions (2 or 3)
// encrypteddata - array of six-bit numbers
void  shifr_streambuf_write3 ( t_ns_shifr * const ns_shifrp ,
  shifr_t_streambuf * const me  , uint8_t const (  * const encrypteddata ) [ 3 ] ,
  uint8_t const secretdatasaltsize , bool const  flagtext ,
  uint8_t * restrict * const output_bufferp , size_t * const writesp ,
  size_t  const outputs ) {
  if  ( flagtext  ) {
    uint8_t i = 0 ;
    do {
      char  buf2  = bits6_to_letter ( ( * encrypteddata ) [ i ] ) ;
        if ( ( * writesp ) >= outputs ) {
          ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
            ( shifr_strcp ) & u8"streambuf_write3: переполнение буфера (flagtext)"  :
            ( shifr_strcp ) & "streambuf_write3: buffer overflow (flagtext)" ) ;
          longjmp ( ns_shifrp  -> jump  , 1 ) ; }
        ( * * output_bufferp ) = ( uint8_t ) buf2 ;
        ++  ( * output_bufferp )  ;
        ++  ( * writesp ) ;
        ++  ( ns_shifrp ->  bytecountw  ) ;
        if  ( ( ns_shifrp ->  bytecountw  ) >=  60  ) {
          if ( ( * writesp ) >= outputs ) {
            ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
              ( shifr_strcp ) & u8"streambuf_write3: переполнение буфера для '\\n'"  :
              ( shifr_strcp ) & "streambuf_write3: buffer overflow for '\\n'" ) ;
            longjmp ( ns_shifrp  -> jump  , 1 ) ; }
          ( * * output_bufferp ) = '\n' ;
          ++  ( * output_bufferp )  ;
          ++  ( * writesp ) ;
          ns_shifrp ->  bytecountw  = 0 ; }
      ++  i ;
    } while ( i < secretdatasaltsize ) ; }
  else  {
    uint8_t i = 0 ;
    do {
      if  ( ( me -> bufbitsize ) < 2 ) {
        me -> buf = ( me -> buf ) bitor
          ( uint8_t ) ( ( ( * encrypteddata ) [ i ] ) << ( me -> bufbitsize ) ) ;
        me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) + 6 ) ; }
      else  {
        uint8_t const to_write  = ( uint8_t ) ( ( ( ( * encrypteddata ) [ i ] ) <<
          ( me -> bufbitsize  ) ) bitor ( me -> buf ) ) ;
        if ( ( * writesp ) >= outputs ) {
          ns_shifrp  -> string_exception  = ( ns_shifrp  -> localerus ? 
            ( shifr_strcp ) & u8"streambuf_write3: переполнение буфера (flagdigit)"  :
            ( shifr_strcp ) & "streambuf_write3: buffer overflow (flagdigit)" ) ;
          longjmp ( ns_shifrp  -> jump  , 1 ) ; }
        ( * * output_bufferp ) = to_write ;
        ++  ( * output_bufferp )  ;
        ++  ( * writesp ) ;
        // + 6 - 8
        me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) - 2U ) ;
        me -> buf = ( uint8_t ) ( ( ( * encrypteddata ) [ i ] ) >>
          ( 6 - ( me -> bufbitsize ) ) ) ;  } 
        ++  i ;
      } while ( i < secretdatasaltsize ) ; } }

// версия 3 пишу три бита для расшифровки
// version 3 write three bits to decode
void  shifr_streambuf_write3bits ( t_ns_shifr * const ns_shifrp ,
  uint8_t const encrypteddata , uint8_t * restrict * const output_bufferp ,
  size_t * const writesp ) {
  shifr_t_streambuf * const restrict me  = & ns_shifrp -> filebufto  ;
  if  ( ( me -> bufbitsize ) < 5 ) {
    me -> buf = ( uint8_t ) ( ( me -> buf ) bitor
      ( encrypteddata <<  ( me -> bufbitsize ) ) ) ;
    me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) + 3U ) ; }
  else  {
    uint8_t const to_write  = ( uint8_t ) ( ( encrypteddata   << (
      me -> bufbitsize ) ) bitor ( me -> buf ) ) ;
    ( * * output_bufferp ) = to_write  ;
    ++  ( * output_bufferp  ) ;
    ++  ( * writesp ) ;
    // + 3 - 8
    me -> bufbitsize = ( uint8_t ) ( ( me -> bufbitsize ) - 5U ) ;
    me -> buf =  ( uint8_t ) ( encrypteddata   >>
      ( 3 - ( me -> bufbitsize ) ) ) ; } }
      
