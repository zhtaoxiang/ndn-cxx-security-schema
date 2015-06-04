/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#ifndef NDN_SECURITY_KEY_CHAIN_SCHEMA_HPP
#define NDN_SECURITY_KEY_CHAIN_SCHEMA_HPP

#include "key-chain.hpp"
#include "schema/schema-interpreter.hpp"
#include "../util/config-file.hpp"

namespace ndn {
namespace security { 
class KeyChainSchema
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  explicit
  KeyChainSchema(const std::string& filename);

  KeyChainSchema();

  virtual
  ~KeyChainSchema()
  {
  }

  template<typename T>
  void
  sign(T& packet);

  void
  load(const std::string& filename);

  void
  load(const std::string& input, const std::string& filename);

  void
  load(std::istream& input, const std::string& filename);

  void
  reset();

  bool
  isEmpty();

  std::vector<std::string>
  getKeyChainNameList();

private:

  bool
  deriveKeyChainNameList(const Name& packetName);

  bool 
  generateKeyName(const std::string& ID,
                       const std::string& pattern);

  Name
  deriveIdentitiName(const std::string& certNamePattern);

  const std::string
  fillRandom(const std::string& patternWithRand);

  const std::string
  patternToUri(const std::string& pattern);

  const std::string
  generateRandStr();

private:
  shared_ptr<KeyChain> m_keyChain;
  shared_ptr<SchemaInterpreter> m_schemaInterpreter;
  std::vector<std::string> m_keyChainNameList;
};

inline std::vector<std::string>
KeyChainSchema::getKeyChainNameList()
{
  return m_keyChainNameList;
}

} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_KEY_CHAIN_SCHEMA_HPP