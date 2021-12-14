from ipfabric import IPFClient
from ipfabric.tools import DeviceConfigs
from cis import CISReport


if __name__ == '__main__':
    ipf = IPFClient()
    cfg = DeviceConfigs(ipf)
    input_hostnames = ['L51AR21']

    print('\n STARTING API script...')
    for hostname in input_hostnames:
        config = cfg.get_configuration(hostname)
        if not config:
            continue
        print(hostname)
        cisreport = CISReport(config.text)
        cisreport.search_config()
        cisreport.print_report(verbose=True)
        """
        Verbose will print a line for each section, for instance a configuration check on username:
        > FAIL 1.2.1 Set 'privilege 1' for local users (Manual)  privilege username username cisco privilege 15 secret 4 
                                                                                                            <omitted>
        > PASS 1.2.1 Set 'privilege 1' for local users (Manual)  privilege username username test secret 4 <omitted>
        
        verbose=False:
        > PARTIAL   1.2.1      Set 'privilege 1' for local users (Manual)
        Partial because one username passed and the other failed
        
        Manual: This script cannot determine based on complexity or requires running a command on the device
        N/A: If not enabled then do not check, for instance skip RIP stuff if RIP is not running.
        """
        print()
        """
        # Results stored in cisreport.results after running search_config
        # Run export on each result to get correct output, example:
        print(cisreport.results[0].export())
        > {'status': 'PASS', 'rule': '1.1.1', 'description': "Enable 'aaa new-model' (Automated)", 
           'match': 'aaa new-model', 'section': None, 'config': None, 'error': None}
        """
    print('\n ENDING API script with success...')

    """
    Read from file:
    """

    # with open('L51AR21.txt', 'r') as f:
    #     cisreoprt = CISReport(f.read())
    # cisreoprt.search_config()
    # cisreoprt.print_report(verbose=True)
