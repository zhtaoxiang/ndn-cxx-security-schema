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


#include "security/key-chain-schema.hpp"
#include "security/validator-schema.hpp"

#include "util/io.hpp"
#include "util/scheduler.hpp"
#include "util/dummy-client-face.hpp"

#include <boost/asio.hpp>

#include "../identity-management-time-fixture.hpp"
#include "boost-test.hpp"

using namespace std;

namespace ndn {
namespace security {
namespace tests {

BOOST_AUTO_TEST_SUITE(SecurityKeyChainSchema)

BOOST_FIXTURE_TEST_CASE(GenerateSigningNameList, IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/haitao/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name dataName("/ndn/edu/ucla/haitao/cs/bh");
  shared_ptr<Data> data = make_shared<Data>(dataName);

    std::string SCHEMA =
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<ucla>(<>)<cs><><>*\n"
    "  signer k1($1,$2)\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id \"k1\"\n"
    "  name (<>*)<ucla>(<>)<config><key><>*\n"
    "  file \"trust-anchor-1.cert\"\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  KeyChainSchema keychain;
  keychain.load(SCHEMA, CONFIG_PATH.native());

  keychain.sign(*data);
  std::vector<std::string> namelist = keychain.getKeyChainNameList();

  BOOST_CHECK_EQUAL(namelist.size(), 1);
  /*for (std::vector<std::string>::iterator it = namelist.begin();
  	it != namelist.end(); ++it)
    {
      BOOST_CHECK_MESSAGE(false, *it);
    }*/
  
  Face face;
  ValidatorSchema validator(face);
  validator.load(SCHEMA, CONFIG_PATH.native());
  validator.validate(*data,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_FIXTURE_TEST_CASE(GenerateSigningNameList2, IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/haitao/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name dataName("/ndn/edu/ucla/haitao/cs/bh");
  shared_ptr<Data> data = make_shared<Data>(dataName);

    std::string SCHEMA =
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<ucla>(<>)<cs><><>*\n"
    "  signer k1($2)|k2($1,$2)\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id \"k2\"\n"
    "  name (<>*)<ucla>(<>)<config><key><>*\n"
    "  file \"trust-anchor-1.cert\"\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  KeyChainSchema keychain;
  keychain.load(SCHEMA, CONFIG_PATH.native());

  keychain.sign(*data);
  std::vector<std::string> namelist = keychain.getKeyChainNameList();

  BOOST_CHECK_EQUAL(namelist.size(), 1);
  /*for (std::vector<std::string>::iterator it = namelist.begin();
  	it != namelist.end(); ++it)
    {
      BOOST_CHECK_MESSAGE(false, *it);
    }*/
  
  Face face;
  ValidatorSchema validator(face);
  validator.load(SCHEMA, CONFIG_PATH.native());
  validator.validate(*data,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });


  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

struct FacesFixture : public security::IdentityManagementTimeFixture
{
  FacesFixture()
    : face1(util::makeDummyClientFace(io, {true, true}))
    , face2(util::makeDummyClientFace(io, {true, true}))
    , readInterestOffset1(0)
    , readDataOffset1(0)
    , readInterestOffset2(0)
    , readDataOffset2(0)
  {
  }

  bool
  passPacket()
  {
    bool hasPassed = false;

    checkFace(face1->sentInterests, readInterestOffset1, *face2, hasPassed);
    checkFace(face1->sentDatas, readDataOffset1, *face2, hasPassed);
    checkFace(face2->sentInterests, readInterestOffset2, *face1, hasPassed);
    checkFace(face2->sentInterests, readDataOffset2, *face1, hasPassed);

    return hasPassed;
  }
  template<typename Packet>
  void
  checkFace(std::vector<Packet>& receivedPackets,
            size_t& readPacketOffset,
            util::DummyClientFace& receiver,
            bool& hasPassed)
  {
    while (receivedPackets.size() > readPacketOffset) {
      receiver.receive(receivedPackets[readPacketOffset]);
      readPacketOffset++;
      hasPassed = true;
    }
  }

  ~FacesFixture()
  {
  }

public:
  shared_ptr<util::DummyClientFace> face1;
  shared_ptr<util::DummyClientFace> face2;

  size_t readInterestOffset1;
  size_t readDataOffset1;
  size_t readInterestOffset2;
  size_t readDataOffset2;
};

BOOST_FIXTURE_TEST_CASE(HierarchicalTrustModel, FacesFixture)
{
  Name root("/TestValidatorSchema");
  BOOST_REQUIRE_NO_THROW(addIdentity(root));
  Name rootCertName = m_keyChain.getDefaultCertificateNameForIdentity(root);
  shared_ptr<IdentityCertificate> rootCert = m_keyChain.getCertificate(rootCertName);
  io::save(*rootCert, "trust-anchor-6.cert");

  Name dataName1("/TestValidatorSchema/Hierarchical/NextLevel");
  shared_ptr<Data> data1 = make_shared<Data>(dataName1);

  const std::string CONFIG =
    "rule \n"
    "{\n"
    "  id \"k1\"\n"
    "  name (<>*)(<>)<KEY><>*\n"
    "  signer k1($1,null)|ac1()\n"
    "}\n"
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<>\n"
    "  signer k1($1,null)|ac1()\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id ac1\n"
    "  name <TestValidatorSchema><KEY><>*<ID-CERT><>*\n"
    "  file \"trust-anchor-6.cert\"\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  KeyChainSchema keychain;
  keychain.load(CONFIG, CONFIG_PATH.native());

  keychain.sign(*data1);
  std::vector<std::string> namelist = keychain.getKeyChainNameList();

  BOOST_CHECK_EQUAL(namelist.size(), 2);
  /*for (std::vector<std::string>::iterator it = namelist.begin();
    it != namelist.end(); ++it)
    {
      BOOST_CHECK_MESSAGE(false, *it);
    }*/

  auto validator = make_shared<ValidatorSchema>(face2.get());
  validator->load(CONFIG, CONFIG_PATH.native());

  advanceClocks(time::milliseconds(2), 100);
  validator->validate(*data1,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });

  do {
    advanceClocks(time::milliseconds(2), 10);
  } while (passPacket());

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace security
} // namespace ndn