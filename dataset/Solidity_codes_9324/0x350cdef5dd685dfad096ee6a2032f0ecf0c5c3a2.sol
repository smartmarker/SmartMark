
pragma solidity 0.6.7;


interface ChainlogAbstract {

    function setAddress(bytes32,address) external;

    function setVersion(string calldata) external;

}


contract SetupChainlogMainnet {

    bool public activated;
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function setup(address addr) public {

        require(owner == msg.sender, "auth-error");

        require(!activated, "already-activated");
        activated = true;

        ChainlogAbstract CHANGELOG = ChainlogAbstract(addr);

        CHANGELOG.setAddress("DEPLOYER", 0xeF6F7Bcd86e1B3fA52f80eE079b0eBd4BceA8EdB);
        CHANGELOG.setAddress("MULTICALL", 0x8B78029AFdB3f9E65912aF6b5b6A3dB99D4c7594);
        CHANGELOG.setAddress("MCD_DEPLOY", 0x6a91178174995d6f43E3D29d57dC7D82b4c7EF15);
        CHANGELOG.setAddress("MCD_GOV", 0xfFED56a180f23fD32Bc6A1d8d3c09c283aB594A8);
        CHANGELOG.setAddress("GOV_GUARD", 0x9cD19fdF40621739620F7Ba4ad47CB111A7B76B1);
        CHANGELOG.setAddress("MCD_IOU", 0xe167b66d5F8692f6fF9de36137B9155345384c3C);
        CHANGELOG.setAddress("MCD_ADM", 0x72FaD6ffF363ec7f39136331416491Aba01EAF4a);
        CHANGELOG.setAddress("VOTE_PROXY_FACTORY", 0x248FEd766B4953B6847a397b291a9Df97B3C2a39);
        CHANGELOG.setAddress("MCD_VAT", 0x694532928Af9288F83AACBa5B932caf51fEC22d5);
        CHANGELOG.setAddress("MCD_JUG", 0xE85993AD2da1Ffd357190F5bCeAAF4233C0F441a);
        CHANGELOG.setAddress("MCD_CAT", 0x8508fcE4D1CC42E753673ECCFA7a7d6F131327E1);
        CHANGELOG.setAddress("MCD_VOW", 0xc15a781D649895628284D2A07212e1a7b2E17C14);
        CHANGELOG.setAddress("MCD_JOIN_DAI", 0x1856298fAD423F63158A3ED1c7d98490840E6C14);
        CHANGELOG.setAddress("MCD_JOIN_USDFL", 0x1856298fAD423F63158A3ED1c7d98490840E6C14);
        CHANGELOG.setAddress("MCD_FLAP", 0x882Ea50e923414D9036C6F344C01350EC0170C52);
        CHANGELOG.setAddress("MCD_FLOP", 0x4A7c5B572792F3D14B2cE51B8D948044b6deC07F);
        CHANGELOG.setAddress("MCD_PAUSE", 0x146921eF7A94C50b96cb53Eb9C2CA4EB25D4Bfa8);
        CHANGELOG.setAddress("MCD_PAUSE_PROXY", 0xd413cAaFd86c3F9AE76cF1e19d95240D3f7176d9);
        CHANGELOG.setAddress("MCD_GOV_ACTIONS", 0x88C2C56A55Ae64cAE81248B34C21C03F1a2B0329);
        CHANGELOG.setAddress("MCD_DAI", 0x2B4200A8D373d484993C37d63eE14AeE0096cd12);
        CHANGELOG.setAddress("MCD_USDFL", 0x2B4200A8D373d484993C37d63eE14AeE0096cd12);
        CHANGELOG.setAddress("MCD_SPOT", 0x12767ED038A80895E45EE3dFF1B7494d49400bEc);
        CHANGELOG.setAddress("MCD_POT", 0x34FADFaABc6dB2dDF7D262d999e561c8F310B6D1);
        CHANGELOG.setAddress("MCD_END", 0x3e12272152125184e9F631864929fCA1cA7c7252);
        CHANGELOG.setAddress("MCD_ESM", 0x6e24943a974A610a0D017E1649EB1eCBDEE16EEF);
        CHANGELOG.setAddress("PROXY_ACTIONS", 0x66883acdDcDFF2DDDECBCBc623B9c40f664C8f1D);
        CHANGELOG.setAddress("PROXY_ACTIONS_END", 0x00dbbaE3e1a5AAD68c4Ad74483c238a517A37964);
        CHANGELOG.setAddress("PROXY_ACTIONS_DSR", 0xB60BCD1A9DFfa777eF2cBb7bAcBDa9FcDD4B6DD6);
        CHANGELOG.setAddress("PROXY_ACTIONS_REWARD", 0xcEe014dE7992D0C5C8a10c6769A12C81b69d0063);
        CHANGELOG.setAddress("PROXY_PAUSE_ACTIONS_ADD", 0x2Db6A8e83B9EBb01699012c3c7dda4Aa85e97289);
        CHANGELOG.setAddress("FL_REWARDER", 0x1a48B6151012a27A4ab2a8c1b8Ec108bAB9eF49c);
        CHANGELOG.setAddress("FL_REWARDER_GOV_USD", 0x975Aa6606f1e5179814BAEf22811441C5060e815);
        CHANGELOG.setAddress("FL_REWARDER_STABLES", 0x5E4935fe0f1f622bfc9521c0e098898e7b8b573c);
        CHANGELOG.setAddress("FL_REWARDER_GOV_USD_HOLDER", 0x34e2B546D1819fE428c072080829028aF36540DD);
        CHANGELOG.setAddress("FL_REWARDER_STABLES_HOLDER", 0x001F7C987996DBD4f1Dba243b0d8891D0Bf693A2);
        CHANGELOG.setAddress("FL_REWARD_AGGREGATOR", 0x51DB1Da6635578B9186B26871038F18351CDD527);
        CHANGELOG.setAddress("FL_REWARD_MAIN_CHECKER_CONTRACT", 0x096835f967D22EC35b78F887c3e9b936b84A3aF7);
        CHANGELOG.setAddress("FL_REWARD_CHECKER_CONTRACT", 0x933B0d1C324f6703536E888ce8C42175e8474283);
        CHANGELOG.setAddress("FL_REWARD_PRICE_PROVIDER", 0x8177E21B333c7488993D89c11f889D78F1eADAE5);
        CHANGELOG.setAddress("FL_UNI_ADAPTER_STABLES", 0x81f6E65493f430D520669E2139F96036102C5331);
        CHANGELOG.setAddress("FL_UNI_ADAPTER_ONE_STABLE", 0xC3dc053e111cA40f148C6E278B180C6F29742569);
        CHANGELOG.setAddress("CDP_MANAGER", 0xB6BEE379CCeB482160f83e0e5018C81bb3807Ede);
        CHANGELOG.setAddress("DSR_MANAGER", 0x0dc36745dB6f36A7bE26b56530c3d62740C5a0cF);
        CHANGELOG.setAddress("GET_CDPS", 0xfb3e3929f12120c0ba1BA243fF8af7afbefB4943);
        CHANGELOG.setAddress("ILK_REGISTRY", 0x0C35421eeEF452804e04734f416d834b0596feA2);
        CHANGELOG.setAddress("OSM_MOM", 0x9273927b1527b7b8fd21296b27b0Ab77DdC00d63);
        CHANGELOG.setAddress("FLIPPER_MOM", 0x4061c702f63A1CA79f3348E44208257228718F0D);
        CHANGELOG.setAddress("PROXY_FACTORY", 0x93b0Cb6ba869b7a90f05e3c233e970df0Ce29557);
        CHANGELOG.setAddress("PROXY_REGISTRY", 0xc08CAa4Cbcc8E8486ceB954b27446EeC16d4Da48);
        CHANGELOG.setAddress("USDCDAI", 0xAE461cA67B15dc8dc81CE7615e0320dA1A9aB8D5);
        CHANGELOG.setAddress("VAL_USDCDAI", 0xc0FbaEeb737487A5B8990515d7eB6AFb404692E7);
        CHANGELOG.setAddress("PIP_USDCDAI", 0xc0FbaEeb737487A5B8990515d7eB6AFb404692E7);
        CHANGELOG.setAddress("MCD_JOIN_USDCDAI_A", 0xef9564d9Ed617173e0c257D08B1EEB90E0e1cF28);
        CHANGELOG.setAddress("MCD_FLIP_USDCDAI_A", 0x835317C1D587971c03940b16d306DF8f4D19bf62);
        CHANGELOG.setAddress("USDTDAI", 0xB20bd5D04BE54f870D5C0d3cA85d82b34B836405);
        CHANGELOG.setAddress("VAL_USDTDAI", 0x826e64E15af1CdcEd00032E985Ee51918397E60F);
        CHANGELOG.setAddress("PIP_USDTDAI", 0x826e64E15af1CdcEd00032E985Ee51918397E60F);
        CHANGELOG.setAddress("MCD_JOIN_USDTDAI_A", 0x8c0929691A458f454cf3438Cf2EF8Bc901a72CcA);
        CHANGELOG.setAddress("MCD_FLIP_USDTDAI_A", 0x2d8b461E9D43C65a7C7E2afeFa5bd1372281Ba63);
        CHANGELOG.setAddress("USDTUSDC", 0x3041CbD36888bECc7bbCBc0045E3B1f144466f5f);
        CHANGELOG.setAddress("VAL_USDTUSDC", 0x81CdB7EB973489526370141A7E3564211dC37Ad8);
        CHANGELOG.setAddress("PIP_USDTUSDC", 0x81CdB7EB973489526370141A7E3564211dC37Ad8);
        CHANGELOG.setAddress("MCD_JOIN_USDTUSDC_A", 0x1B9C400E36239c2649391c0179D9C3799c94fA6F);
        CHANGELOG.setAddress("MCD_FLIP_USDTUSDC_A", 0x792560e6FeD8887a7B7b22E179d3A3fc43933AcB);
        CHANGELOG.setAddress("USDTUSDN", 0x73Fb253681C2a2F11C9D5C8e731bE44A3F46B353);
        CHANGELOG.setAddress("VAL_USDTUSDN", 0x85FE3913Bc913f5C67B9AE3B7cc2785746979fec);
        CHANGELOG.setAddress("PIP_USDTUSDN", 0x85FE3913Bc913f5C67B9AE3B7cc2785746979fec);
        CHANGELOG.setAddress("MCD_JOIN_USDTUSDN_A", 0x18C480a97c5F36d6bB185741ad5df9ab9361050A);
        CHANGELOG.setAddress("MCD_FLIP_USDTUSDN_A", 0x07C5f5eb34019EB36CdaE8CBb625991c1202cbDa);
        CHANGELOG.setAddress("PROXY_PAUSE_ACTIONS", 0x45d6a1D01E37aedC0e1Af6ff6a87D25754cA8ECB);
        CHANGELOG.setAddress("PROXY_DEPLOYER", 0x499aCCC4c56758d2A3Ef889dA4c975D30DCFA44a);

        CHANGELOG.setVersion("1.0.0");
    }
}