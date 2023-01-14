// Shifr ©2020-3 Glebe A.N. constants
// Шифр ©2020-3 Глебов А.Н. константы

# ifndef  SHIFR_NUMBER_ENUM_H
# define  SHIFR_NUMBER_ENUM_H

# define  shifr_number_size( N ) shifr_number_size_ ## N

// log(2,16!) ceil 8 = 6
// log(2,64!) ceil 8 = 37
enum  shifr_e_number_size {
  shifr_number_size ( v2 )  = 6 ,
  shifr_number_size ( v3 )  = 37  ,
} ;

# endif // SHIFR_NUMBER_ENUM_H
