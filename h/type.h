// Shifr ©2020-3 Glebe A.N. types
// Шифр ©2020-3 Глебов А.Н. типы

# ifndef  SHIFR_TYPE_H
# define  SHIFR_TYPE_H

typedef char ( * shifr_strp ) [ ] ;
typedef char  volatile  ( * shifr_strvp ) [ ] ;
typedef char const ( * shifr_strcp  ) [ ] ;
typedef char  volatile  const ( * shifr_strvcp  ) [ ] ;

# include <stdint.h>

typedef uint8_t ( * shifr_arrp  ) [ ] ;
typedef uint8_t const ( * shifr_arrcp ) [ ] ;
typedef uint8_t volatile  ( * shifr_arrvp ) [ ] ;
typedef uint8_t volatile  const ( * shifr_arrvcp  ) [ ] ;
struct  shifr_s_arrcps  ;
typedef struct  shifr_s_arrcps  shifr_arrcps  ;
struct  shifr_s_arrps ;
typedef struct  shifr_s_arrps shifr_arrps ;
struct  shifr_s_size_io ;
typedef struct  shifr_s_size_io shifr_size_io ;

# define struct_raspr( V ) struct  shifr_s_raspr_ ## V

struct_raspr ( v2 ) ;
struct_raspr ( v3 ) ;

# define  shifr_t_raspr( V ) shifr_t_raspr_ ## V

typedef struct_raspr ( v2 ) shifr_t_raspr ( v2 ) ;

typedef struct_raspr ( v3 ) shifr_t_raspr ( v3 ) ;

struct  s_ns_shifr  ;
typedef struct  s_ns_shifr  t_ns_shifr ;

struct  shifr_s_streambuf ;
typedef struct  shifr_s_streambuf shifr_t_streambuf ;

# define  shifr_deshi_size( V ) shifr_deshi_size_ ## V

// 4^2 = 16 = 0x10
// 4^3 = 64 = 0x40

enum  shifr_e_deshi_size  {
  shifr_deshi_size ( v2 ) = 0x10 ,
  shifr_deshi_size ( v3 ) = 0x40 ,
} ;

typedef enum  shifr_e_deshi_size  shifr_t_deshi_size  ;

# include "define.h"

# ifdef SHIFR_DEBUG

typedef long  long  int shifr_timestamp_t ;

# endif // SHIFR_DEBUG
# endif //  SHIFR_TYPE_H
