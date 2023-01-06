// make example && ./example
# include "inline.h"

int main  ( int argc , char * argv [ ] ) {
  t_ns_shifr  shif ;
  shifr_init  ( & shif ) ;
  shif  . use_version = 3 ;
  shif  . flagtext = true  ;
  shifr_password_set_by_string  ( & shif , "qwerty" ) ;
  enum { inbufsize = 0x100 } ;
  uint8_t inbuf [ inbufsize ] = "Lambda" ;
  
  enum { outbufsize = 0x400 } ;
  uint8_t outbuf [ outbufsize ] ;
  shifr_size_io sizeio  = shifr_encrypt3  ( & shif ,
    ( shifr_arrcps ) { .cp = ( shifr_arrcp ) & inbuf ,
      .s = strlen ( (char const*)inbuf ) } ,
    ( shifr_arrps ) { .p = & outbuf , .s = outbufsize - 1 } ) ;
  fprintf ( stdout , "inbuf = `%s`\n" , inbuf ) ;
  outbuf [ sizeio . o ] = '\00' ;
  fprintf ( stdout , "  outbuf = `%s`\n" , outbuf ) ;
  strcpy ( (char *)inbuf , " !" ) ;
  
  enum { outbuf2size = 0x400 } ;
  uint8_t outbuf2 [ outbuf2size ] ;
  shifr_size_io sizeio2  = shifr_encrypt3  ( & shif ,
    ( shifr_arrcps ) { .cp = ( shifr_arrcp ) & inbuf ,
      .s = strlen ( (char const*)inbuf ) } ,
    ( shifr_arrps ) { .p = & outbuf2 , .s = outbuf2size - 1 } ) ;
  fprintf ( stdout , "second inbuf = `%s`\n" , inbuf ) ;
  outbuf2 [ sizeio2 . o ] = '\00' ;
  fprintf ( stdout , "  second outbuf = `%s`\n" , outbuf2 ) ;
  
  enum { outbuffsize = 0x40 } ;
  uint8_t outbuff [ outbuffsize ] ;
  
  uint8_t const bytes = shifr_flush ( & shif ,
          ( shifr_arrps ) { .p = & outbuff , .s = outbuffsize - 1 } ) ;
  outbuff [ bytes ] = '\00' ;
  fprintf ( stdout , "  flush outbuf = `%s`\n" , outbuff ) ;
  fprintf ( stdout , "  full string = `%s" , outbuf ) ;
  fputs ( (char *)outbuf2 , stdout ) ;
  fprintf ( stdout , "%s`\n" , outbuff ) ;
  
  fputs ( "--- decrypt ---\n" , stdout ) ;
  
  shifr_salt_init ( & shif  ) ;
  
  enum { decbufsize = 0x100 } ;
  uint8_t decbuf [ decbufsize ] ;
  shifr_size_io sizeiodec  = shifr_decrypt3  ( & shif ,
    ( shifr_arrcps  ) { . cp  = ( shifr_arrcp ) & outbuf , . s = sizeio . o } ,
    ( shifr_arrps ) { . p = & decbuf , . s = decbufsize - 1 } ) ;
  fprintf ( stdout , "outbuf = `%s`\n" , outbuf ) ;
  decbuf [ sizeiodec . o ] = '\00' ;
  fprintf ( stdout , "  decbuf = `%s`\n" , decbuf ) ;
  
  enum { decbuf2size = 0x100 } ;
  uint8_t decbuf2 [ decbuf2size ] ;
  shifr_size_io sizeiodec2  = shifr_decrypt3  ( & shif ,
    ( shifr_arrcps  ) { . cp  = ( shifr_arrcp ) & outbuf2 ,
      . s = sizeio2 . o } ,
    ( shifr_arrps ) { . p = & decbuf2 , . s = decbuf2size - 1 } ) ;
  fprintf ( stdout , "second outbuf = `%s`\n" , outbuf2 ) ;
  decbuf2 [ sizeiodec2 . o ] = '\00' ;
  fprintf ( stdout , "  second decbuf = `%s`\n" , decbuf2 ) ;
  
  enum { decbuffsize = 0x10 } ;
  uint8_t decbuff [ decbuffsize ] ;
  shifr_size_io sizeiodecf  = shifr_decrypt3  ( & shif ,
    ( shifr_arrcps  ) { . cp  = ( shifr_arrcp ) & outbuff ,
      . s = bytes } ,
    ( shifr_arrps ) { . p = & decbuff , . s = decbuffsize - 1 } ) ;
  fprintf ( stdout , "flush outbuf = `%s`\n" , outbuff ) ;
  decbuff [ sizeiodecf . o ] = '\00' ;
  fprintf ( stdout , "  flush decbuf = `%s`\n" , decbuff ) ;  
  
  fprintf ( stdout , "  full string = `%s" , decbuf ) ;
  fputs ( (char *)decbuf2 , stdout ) ;
  fprintf ( stdout , "%s`\n" , decbuff ) ;
  
  shifr_destr ( & shif ) ;
}
