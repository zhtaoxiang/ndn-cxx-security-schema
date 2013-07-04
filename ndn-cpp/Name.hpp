/* 
 * Author: Jeff Thompson
 *
 * BSD license, See the LICENSE file for more information.
 */

#ifndef NDN_NAME_HPP
#define	NDN_NAME_HPP

#include <vector>
#include <string>
#include "common.h"
#include "c/Name.h"
#include "encoding/BinaryXMLWireFormat.hpp"

namespace ndn {
  
class NameComponent {
public:
  NameComponent() 
  {    
  }
  
  NameComponent(unsigned char * value, unsigned int valueLen) 
  : value_(value, value + valueLen)
  {
  }
  
  /**
   * Set the componentStruct to point to this component, without copying any memory.
   * WARNING: The resulting pointer in componentStruct is invalid after a further use of this object which could reallocate memory.
   * @param componentStruct the C ndn_NameComponent struct to receive the pointer.
   */
  void get(struct ndn_NameComponent &componentStruct) 
  {
    componentStruct.value = &value_[0];
    componentStruct.valueLength = value_.size(); 
  }
  
  /**
   * Set this component value by decoding the escapedString between first and last according to the NDN URI Scheme.
   * If the escaped string is "", "." or ".." then return false, which means this component value was not changed, and
   * the component should be skipped in a URI name.
   * @param first pointer to the beginning of the escaped string
   * @param last pointer to the first character past the end of the escaped string
   * @return true for success, false if escapedString is not a valid escaped component.
   */
  bool setFromEscapedString(const char *first, const char *last);
  
  const std::vector<unsigned char> &getValue() const { return value_; }
  
private:
  std::vector<unsigned char> value_;
}; 
  
class Name {
public:
  /**
   * Create a new Name with no components.
   */
  Name() {
  }
  
  /**
   * Parse the uri according to the NDN URI Scheme and create the name with the components.
   * @param uri the URI string.
   */
  Name(const char *uri);
  
  void encode(std::vector<unsigned char> &output, WireFormat &wireFormat) 
  {
    wireFormat.encodeName(*this, output);
  }
  void encode(std::vector<unsigned char> &output) 
  {
    encode(output, BinaryXMLWireFormat::instance());
  }
  void decode(const unsigned char *input, unsigned int inputLength, WireFormat &wireFormat) 
  {
    wireFormat.decodeName(*this, input, inputLength);
  }
  void decode(const unsigned char *input, unsigned int inputLength) 
  {
    decode(input, inputLength, BinaryXMLWireFormat::instance());
  }
  void decode(const std::vector<unsigned char> &input, WireFormat &wireFormat) 
  {
    decode(&input[0], input.size(), wireFormat);
  }
  void decode(const std::vector<unsigned char> &input) 
  {
    decode(&input[0], input.size());
  }
  
  /**
   * Set the nameStruct to point to the components in this name, without copying any memory.
   * WARNING: The resulting pointers in nameStruct are invalid after a further use of this object which could reallocate memory.
   * @param nameStruct a C ndn_Name struct where the components array is already allocated.
   */
  void get(struct ndn_Name &nameStruct);
  
  /**
   * Clear this name, and set the components by copying from the name struct.
   * @param nameStruct a C ndn_Name struct
   */
  void set(struct ndn_Name &nameStruct);
  
  /**
   * Add a new component, copying from value of length valueLength.
   */
  void addComponent(unsigned char *value, unsigned int valueLength) {
    components_.push_back(NameComponent(value, valueLength));
  }
  
  /**
   * Clear all the components.
   */
  void clear() {
    components_.clear();
  }
  
  /**
   * Get the number of components.
   * @return the number of components
   */
  unsigned int getComponentCount() {
    return components_.size();
  }
  
  const NameComponent &getComponent(unsigned int i) const { return components_[i]; }
  
  /**
   * Encode this name as a URI.
   * @return the encoded URI.
   */
  std::string to_uri();
  
private:
  std::vector<NameComponent> components_;
};  

}

#endif
