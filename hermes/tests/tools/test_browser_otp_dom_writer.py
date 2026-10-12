"""Execute the actual generated OTP scripts against a controlled DOM fixture.

This fixture models synchronous event rejection and inspection stamps. It does
not claim to reproduce a merchant, framework, or trusted browser editing event.
"""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from agent.vault_login_classifier import (
    LoginControl,
    build_fill_js,
    build_inspection_js,
    build_otp_fills,
    classify_otp_controls,
)


ORIGIN = "https://accounts.example.invalid"
SYNTHETIC_CODE = "592741"

DOM_FIXTURE = r"""
const fs=require('fs'), vm=require('vm');
const data=JSON.parse(fs.readFileSync(0,'utf8'));
const state={writes:0,untrusted:0,accepted:0};
let document;
class Input {
  constructor(index){
    this.index=index;this._value='';this.saved='';this.attrs={};
    this.isConnected=true;this.disabled=false;this.readOnly=false;
    this.tagName='INPUT';this.type='tel';this.autocomplete='one-time-code';
    this.maxLength=data.count===1?6:1;this.name='otp'+index;this.id=this.name;
    this.labels=[{textContent:'Verification code'}];this.form=null;
  }
  get value(){return this._value;}
  set value(value){state.writes++;this._value=String(value);}
  setAttribute(key,value){this.attrs[key]=String(value);}
  getAttribute(key){return this.attrs[key]||null;}
  removeAttribute(key){delete this.attrs[key];}
  getClientRects(){return this.isConnected?[{}]:[];}
  focus(){document.activeElement=this;}
  dispatchEvent(event){
    if(event.type==='input'){
      if(!event.isTrusted)state.untrusted++;
      if(data.mode==='controlled'&&!event.isTrusted)this._value=this.saved;
      else {this.saved=this._value;state.accepted++;}
    }
  }
}
const elements=Array.from({length:data.count},(_,index)=>new Input(index));
const form={};elements.forEach(el=>el.form=form);
document={
  activeElement:null,forms:[form],
  querySelectorAll(selector){
    if(selector==='input, select')return elements;
    if(selector==='[data-hermes-vault-slot]')return elements.filter(el=>el.attrs['data-hermes-vault-slot']);
    throw Error('Unsupported fixture selector');
  },
  querySelector(selector){
    const match=selector.match(/^\[data-hermes-vault-slot="([^"]+)"\]$/);
    if(!match)throw Error('Unsupported fixture target');
    return elements.find(el=>el.attrs['data-hermes-vault-slot']===match[1])||null;
  },
  getElementById(id){return elements.find(el=>el.id===id)||null;}
};
const context={document,HTMLInputElement:Input,
  window:{location:{origin:data.origin}},
  getComputedStyle:()=>({display:'block',visibility:'visible'}),
  InputEvent:class {constructor(type){this.type=type;this.isTrusted=false;}},
  Event:class {constructor(type){this.type=type;this.isTrusted=false;}}
};
const inspection=JSON.parse(vm.runInNewContext(data.inspection,context));
if(data.intervening)vm.runInNewContext(data.intervening,context);
if(data.reorder)elements.reverse();
const result=JSON.parse(vm.runInNewContext(data.writer,context));
const expected=Object.fromEntries(data.expected.map(item=>[item.index,item.value]));
process.stdout.write(JSON.stringify({result,inspection_count:inspection.length,
  exact_values:elements.every(el=>el.value===expected[el.index]),
  all_empty:elements.every(el=>el.value===''),
  remaining_stamps:elements.filter(el=>el.attrs['data-hermes-vault-slot']).length,
  writes:state.writes,untrusted_inputs:state.untrusted,accepted_inputs:state.accepted}));
"""


def otp_fills(count):
    controls = [LoginControl("one-time-code", 0, index, "Verification code", "otp" + str(index),
                             "tel", 6 if count == 1 else 1) for index in range(count)]
    return build_otp_fills(classify_otp_controls(controls), SYNTHETIC_CODE)


def execute_writer(tmp_path, count, *, mode="accept", origin=ORIGIN, intervening="", reorder=False):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to execute the generated OTP writer")
    fixture = tmp_path / "otp-dom.js"
    fixture.write_text(DOM_FIXTURE)
    fills = otp_fills(count)
    completed = subprocess.run(
        [node, str(fixture)],
        input=json.dumps({
            "count": count, "mode": mode, "origin": origin, "intervening": intervening,
            "reorder": reorder, "inspection": build_inspection_js("prepared-otp"),
            "writer": build_fill_js(fills, expected_origin=ORIGIN, nonce="prepared-otp"),
            "expected": fills,
        }),
        text=True, capture_output=True, check=True, timeout=10,
    )
    assert SYNTHETIC_CODE not in completed.stdout
    return json.loads(completed.stdout)


@pytest.mark.parametrize("count", [1, 6])
def test_generated_writer_accepts_single_and_split_otp_without_echo(tmp_path, count):
    result = execute_writer(tmp_path, count)
    assert result["result"] == {"filled": count}
    assert result["inspection_count"] == count
    assert result["exact_values"] is True
    assert result["remaining_stamps"] == 0


@pytest.mark.parametrize("count", [1, 6])
def test_controlled_otp_rejects_actual_synthetic_input_events(tmp_path, count):
    result = execute_writer(tmp_path, count, mode="controlled")
    assert result["result"] == {"filled": 0}
    assert result["all_empty"] is True
    assert result["writes"] == count
    assert result["untrusted_inputs"] == count
    assert result["accepted_inputs"] == 0
    assert result["remaining_stamps"] == 0


@pytest.mark.parametrize("count", [1, 6])
def test_an_intervening_inspection_invalidates_old_slots_without_input(tmp_path, count):
    # Login/form probes use the same real inspector with their own nonce.
    result = execute_writer(tmp_path, count,
                            intervening=build_inspection_js("clanker-login-probe"))
    assert result["result"] == {"filled": 0}
    assert result["all_empty"] is True
    assert result["writes"] == result["untrusted_inputs"] == 0


@pytest.mark.parametrize("count", [1, 6])
def test_wrong_origin_refuses_before_any_setter_or_input_event(tmp_path, count):
    result = execute_writer(tmp_path, count, origin="https://other.example.invalid")
    assert result["result"]["refused"] == "origin_changed"
    assert result["all_empty"] is True
    assert result["writes"] == result["untrusted_inputs"] == 0


@pytest.mark.parametrize("count", [1, 6])
def test_dom_reordering_keeps_inspected_nodes_instead_of_position_targets(tmp_path, count):
    result = execute_writer(tmp_path, count, reorder=True)
    assert result["result"] == {"filled": count}
    assert result["exact_values"] is True
