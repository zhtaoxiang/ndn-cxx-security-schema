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

#include "key-chain-schema.hpp"
#include "certificate-cache-ttl.hpp"
#include "../util/io.hpp"
#include "schema/signature-requirement.hpp"

#include <boost/filesystem.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/algorithm/string.hpp>

#include <iostream>
#include <string>
#include <sstream>

namespace ndn {
namespace security {

KeyChainSchema::KeyChainSchema()
  : m_keyChain(make_shared<KeyChain>())
  , m_schemaInterpreter(make_shared<SchemaInterpreter>())
{
}

KeyChainSchema::KeyChainSchema(const std::string& filename)
  : m_keyChain(make_shared<KeyChain>())
  , m_schemaInterpreter(make_shared<SchemaInterpreter>())
{
  load(filename);
}

void
KeyChainSchema::load(const std::string& filename)
{
  std::ifstream inputFile;
  inputFile.open(filename.c_str());
  if (!inputFile.good() || !inputFile.is_open()) 
    {
      std::string msg = "Failed to read configuration file: ";
      msg += filename;
      throw Error(msg);
    }
    load(inputFile, filename);
    inputFile.close();
}

void
KeyChainSchema::load(const std::string& input, const std::string& filename)
{
  std::istringstream inputStream(input);
  load(inputStream, filename);
}

void
KeyChainSchema::load(std::istream& input, const std::string& filename)
{
  m_schemaInterpreter->load(input, filename);
}

template<typename T>
void
KeyChainSchema::sign(T& packet)
{
  m_keyChainNameList.clear();
  if (!deriveKeyChainNameList(packet.getName()))
    {
      throw Error("Sign failed. Cannot generate key chain");
      return;
    }

  shared_ptr<const SignatureRequirement> sigReq1 = m_schemaInterpreter->getSigReq();
  SignatureRequirement sigReq = *sigReq1;
  // prepare the signing parameters
  time::system_clock::TimePoint notBefore = time::system_clock::now();
  time::system_clock::TimePoint notAfter = notAfter + time::days(365);
  std::vector<CertificateSubjectDescription> subjectDescription;
  const std::unordered_set<uint32_t> signPolicy = sigReq.getSigningPolicies();

  std::vector<std::string>::reverse_iterator rit = m_keyChainNameList.rbegin();
  
  Name signerCertName = Name(*rit);
  Name signerPulicKeyName = IdentityCertificate::certificateNameToPublicKeyName(signerCertName);
  Name signerIdentityName = signerPulicKeyName.getSubName(0, signerPulicKeyName.size() - 1);
  
  Name identityName, keyName;
  std::string certNamePattern;
  shared_ptr<IdentityCertificate> certificate;
  bool isKsk = true;

  for (++ rit; rit != m_keyChainNameList.rend(); ++rit)
    {
      certNamePattern = *rit;
      identityName = deriveIdentitiName(certNamePattern);

      isKsk = rit + 1 == m_keyChainNameList.rend() ? false : true;
      if (signPolicy.find(tlv::SignatureSha256WithRsa) != signPolicy.end())
        {
          keyName = m_keyChain->generateRsaKeyPairAsDefault(identityName, isKsk, 
          	sigReq.getKeySize());
        }
      else if (signPolicy.find(tlv::SignatureSha256WithEcdsa) != signPolicy.end())
        {
      	  keyName = m_keyChain->generateEcdsaKeyPairAsDefault(identityName, isKsk,
      	  	sigReq.getKeySize());
        }
      else if (signPolicy.find(tlv::DigestSha256) != signPolicy.end())
        {
          throw Error("Current schema does not support pure sha-256 signature type.");
          return;
        }
      else
        {
          throw Error("Current schema does not support the signature type you provide.");
          return;
        }
      certificate =
        m_keyChain->prepareUnsignedIdentityCertificate(keyName, 
                                                    signerIdentityName,
                                                    notBefore, 
                                                    notAfter,
                                                    subjectDescription);
      m_keyChain->sign(*certificate, signerCertName);
      m_keyChain->addCertificateAsIdentityDefault(*certificate);
      signerCertName = certificate->getName();
    }
    m_keyChain->sign(packet, signerCertName);
}

template void
KeyChainSchema::sign(ndn::Data& packet);

template void
KeyChainSchema::sign(ndn::Interest& packet);

bool
KeyChainSchema::deriveKeyChainNameList(const Name& packetName)
{
  std::vector<std::pair<std::string, std::string>> patterns 
      = m_schemaInterpreter->deriveSignerPatternFromName(packetName);

  for (std::vector<std::pair<std::string, std::string>>::iterator it = patterns.begin();
       it != patterns.end(); ++it)
    {
      shared_ptr<const Certificate> cert = m_schemaInterpreter->getCertificate(it->first);
      if (cert != nullptr)
        {
          m_keyChainNameList.push_back(cert->getName().toUri());
          return true;
        }

      if (generateKeyName(it->first, it->second))
        {
          return true;
        }
    }
  return false;
}

bool
KeyChainSchema::generateKeyName(const std::string& ID,
                                const std::string& pattern)
{
  std::vector<std::pair<std::string, std::string>> patterns 
      = m_schemaInterpreter->derivePatternFromRuleId(ID);
  for (std::vector<std::pair<std::string, std::string>>::iterator it = patterns.begin();
       it != patterns.end(); ++it)
    {
      // If reaches trust anchor
      shared_ptr<const Certificate> cert = m_schemaInterpreter->getCertificate(it->first);
      if (cert != nullptr)
        {
          m_keyChainNameList.push_back(cert->getName().toUri());
          return true;
        }

      // If we have seen the same pattern or not
      bool found = false;
      for (std::vector<std::string>::iterator nameStr = m_keyChainNameList.begin();
        nameStr != m_keyChainNameList.end(); ++nameStr)
        {
          if (nameStr->compare(std::get<1>(*it)) == 0)
          {
            found = true;
            break;
          }
        }
      if (found)
        continue;
      
      m_keyChainNameList.push_back(std::get<1>(*it));
      if (generateKeyName(it->first, it->second))
        {
      	  return true;
        }
      m_keyChainNameList.pop_back();
    }
  return false;
}

Name
KeyChainSchema::deriveIdentitiName(const std::string& certNamePattern)
{
  Name result;
  size_t pos = 0;
  if ((pos = certNamePattern.find("<KEY>")) == std::string::npos) 
    {
      throw Error("One schema rule does not contain <KEY> component");
    }
  std::string beforeKeyComponent = certNamePattern.substr(0, pos);
  std::string afterKeyComponent = certNamePattern.substr(pos + 5);
  std::string beforeSKComponent = "";
  if ((pos = afterKeyComponent.find("<ksk")) != std::string::npos
    || (pos = afterKeyComponent.find("<dsk")) != std::string::npos)
    {
      std::string beforeSKComponent = afterKeyComponent.substr(0, pos);
    }
  else if ((pos = afterKeyComponent.find("<ID-CERT>")) != std::string::npos)
    {
      pos = afterKeyComponent.rfind("<", pos - 1);
      std::string beforeSKComponent = afterKeyComponent.substr(0, pos);
    }
  else if ((pos = afterKeyComponent.rfind("<><><>")) == afterKeyComponent.size() - 6)
    {
      std::string beforeSKComponent = afterKeyComponent.substr(0, pos);
    } 
  else if ((pos = afterKeyComponent.rfind("<>*")) != std::string::npos)
    {
      std::string beforeSKComponent = afterKeyComponent.substr(0, pos);
    }
  std::string resultPattern = fillRandom(beforeKeyComponent);
  resultPattern = resultPattern.append(fillRandom(beforeSKComponent));
  result = Name(patternToUri(resultPattern));
  return result;
}

const std::string
KeyChainSchema::fillRandom(const std::string& patternWithRand)
{
  std::string result = patternWithRand;
  size_t pos = 0;
  while ((pos = result.find("<>*")) != std::string::npos)
    {
      result = result.replace(pos, 3, "");
    }
  while ((pos = result.find("<>")) != std::string::npos)
    {
      result = result.replace(pos, 2, generateRandStr());
    }
  return result;
}

const std::string
KeyChainSchema::generateRandStr()
{
  std::stringstream ss;
  ss << "<" << time::system_clock::now() << ">";
  std::string result = ss.str();
  return result;
}

const std::string
KeyChainSchema::patternToUri(const std::string& pattern)
{
  std::string result = pattern;
  size_t pos = 0;
  while ((pos = result.find("><")) != std::string::npos)
    {
      result = result.replace(pos, 2, "/");
    }
  result = result.replace(0, 1, "/");
  result = result.replace(result.size() - 1, 1, "");
  return result;
}

} //namespace security
} //namespace ndn