#ifndef SRC_INCLUDE_GENTEST_BRIDGE_H_
#define SRC_INCLUDE_GENTEST_BRIDGE_H_

#ifdef __cplusplus
extern "C"
#endif 

/**
 * Create a file containing standalone tests.
 * @param output_filename Path of the file to write the standalone
 *        test to.
 * @param input_source_filename The name of the c/cpp file that is the 
 *        original source of the test. 
 * @param binary_filename The name of the file containing binary test data.
 * @param translation_config_filename The name of the file containing the translation 
 *        configuration data.
 * @note I would like 'input_source_filename' to be determined automatically,
 *       but it's not yet clear how that should be done.
 * @returns 0 on successful execution, non-zero otherwise.
 **/
int DeepStateCreateStandalone( const char *output_filename,
                               const char *input_source_filename,
                               const char *binary_filename,
                               const char *translation_config_filename,
			       const char *input_dir,
                               const char *run_num,
			       const bool standard_fuzz,
			       const bool fuzz_until_fail,
			       const char * test_case	       
                             );


#endif // SRC_INCLUDE_GENTEST_BRIDGE_H_
