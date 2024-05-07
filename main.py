from collections import namedtuple
from typing import Optional
from typing_extensions import Annotated

import typer
import dns.resolver
import dns.dnssec
from rich import print

Alias = namedtuple(
    "Alias",
    ["source", "oa1", "recipient_address", "recipient_name", "tx_description"],
)


class DNSSECNotPassed(Exception):
    pass


def parse(answer: str, source: str):
    dictionary = dict()
    OA1_CONST = "oa1"
    if not answer.startswith(OA1_CONST):
        return None
    values = answer.split(";")
    oa1 = values[0].split(" ")[0].split(":")[1]
    values[0] = values[0].split(" ")[1]
    values = values[:-1]
    parsed = {}
    for value in values:
        key, val = value.split("=")
        parsed[key.strip()] = val.strip()
    return Alias(
        source,
        oa1,
        parsed["recipient_address"],
        parsed["recipient_name"],
        parsed["tx_description"],
    )


def check_dnssec(alias: str):
    raise NotImplemented


def workflow(alias: str, strong: bool):
    original_alias = alias
    # check if we have a valid DNSSEC trust chain (RRSIG, DNSKEY, NSEC3),
    # if not then alert the user that it is potentially untrusted, continue
    # if the user agrees
    try:
        check_dnssec(alias)
    except:
        if strong:
            raise DNSSECNotPassed
    result = None
    is_address = False
    # if the value entered contains an @ character,
    # replace it with a . (period) character to allow
    # for email-style addressing
    if "@" in alias:
        alias = alias.replace("@", ".")
    # check that the value entered contains a . (period) character,
    # if not then it is an address and not an FQDN
    if "." not in alias:
        is_address = True
        return result, is_address
    # fetch all of the TXT records for the FQDN, retry at least 3 times on
    # failure, handle an overall failure in the lookup
    try:
        answers = dns.resolver.resolve(alias, "TXT")
    except:
        return result, is_address
    # step through each of the TXT records and make sure we have
    # the oa1 (OpenAlias version 1) prefix followed by the prefix for
    # our application (oa1:xmr in our example), break on the first match
    #  (ignoring later matches unless your application specifically supports
    # handling multiple records)
    result = []
    for answr in answers:
        answer: str = answr.to_text().strip('"')
        res = parse(answer, original_alias)
        if res:
            result.append(res)
    return result


def main(
    alias: Annotated[str, typer.Argument(help="The email or FQDN")],
    check_dnssec: Annotated[bool, typer.Option()] = True,
):
    if check_dnssec:
        print(
            "[bold red]DANGEROUS![/bold red], Checking DNSSEC is not implemented currently."
        )
        c = typer.confirm("DNSSEC is not valid. Do you want to continue?")
    if not c:
        exit(-1)
    result = workflow(alias, False)
    for res in result:
        print(res._asdict())


if __name__ == "__main__":
    typer.run(main)
